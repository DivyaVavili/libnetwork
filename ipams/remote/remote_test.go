package remote

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/docker/docker/pkg/plugins"
	"github.com/docker/libkv/store"
	"github.com/docker/libnetwork/datastore"
	"github.com/docker/libnetwork/ipamapi"
	_ "github.com/docker/libnetwork/testutils"
)

func decodeToMap(r *http.Request) (res map[string]interface{}, err error) {
	err = json.NewDecoder(r.Body).Decode(&res)
	return
}

func handle(t *testing.T, mux *http.ServeMux, method string, h func(map[string]interface{}) interface{}) {
	mux.HandleFunc(fmt.Sprintf("/%s.%s", ipamapi.PluginEndpointType, method), func(w http.ResponseWriter, r *http.Request) {
		ask, err := decodeToMap(r)
		if err != nil && err != io.EOF {
			t.Fatal(err)
		}
		answer := h(ask)
		err = json.NewEncoder(w).Encode(&answer)
		if err != nil {
			t.Fatal(err)
		}
	})
}

func setupPlugin(t *testing.T, name string, mux *http.ServeMux) func() {
	if err := os.MkdirAll("/etc/docker/plugins", 0755); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(mux)
	if server == nil {
		t.Fatal("Failed to start a HTTP Server")
	}

	if err := ioutil.WriteFile(fmt.Sprintf("/etc/docker/plugins/%s.spec", name), []byte(server.URL), 0644); err != nil {
		t.Fatal(err)
	}

	mux.HandleFunc("/Plugin.Activate", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.docker.plugins.v1+json")
		fmt.Fprintf(w, `{"Implements": ["%s"]}`, ipamapi.PluginEndpointType)
	})

	return func() {
		if err := os.RemoveAll("/etc/docker/plugins"); err != nil {
			t.Fatal(err)
		}
		server.Close()
	}
}

func TestGetCapabilities(t *testing.T) {
	var plugin = "test-ipam-driver-capabilities"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetCapabilities", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"RequiresMACAddress": true,
		}
	})

	p, err := plugins.Get(plugin, ipamapi.PluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	d := newAllocator(plugin, p.Client)

	caps, err := d.(*allocator).getCapabilities()
	if err != nil {
		t.Fatal(err)
	}

	if !caps.RequiresMACAddress {
		t.Fatalf("Unexpected capability: %v", caps)
	}
}

func TestGetCapabilitiesFromLegacyDriver(t *testing.T) {
	var plugin = "test-ipam-legacy-driver"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	p, err := plugins.Get(plugin, ipamapi.PluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	d := newAllocator(plugin, p.Client)

	if _, err := d.(*allocator).getCapabilities(); err == nil {
		t.Fatalf("Expected error, but got Success %v", err)
	}
}

func TestGetDefaultAddressSpaces(t *testing.T) {
	var plugin = "test-ipam-driver-addr-spaces"

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetDefaultAddressSpaces", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"LocalDefaultAddressSpace":  "white",
			"GlobalDefaultAddressSpace": "blue",
		}
	})

	p, err := plugins.Get(plugin, ipamapi.PluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	d := newAllocator(plugin, p.Client)

	l, g, err := d.(*allocator).GetDefaultAddressSpaces()
	if err != nil {
		t.Fatal(err)
	}

	if l != "white" || g != "blue" {
		t.Fatalf("Unexpected default local and global address spaces: %s, %s", l, g)
	}
}

func getRemoteAllocator(plugin string, t *testing.T) (ipamapi.Ipam, error) {

	mux := http.NewServeMux()
	defer setupPlugin(t, plugin, mux)()

	handle(t, mux, "GetDefaultAddressSpaces", func(msg map[string]interface{}) interface{} {
		return map[string]interface{}{
			"LocalDefaultAddressSpace":  "white",
			"GlobalDefaultAddressSpace": "blue",
		}
	})

	handle(t, mux, "RequestPool", func(msg map[string]interface{}) interface{} {
		as := "white"
		if v, ok := msg["AddressSpace"]; ok && v.(string) != "" {
			as = v.(string)
		}

		pl := "172.18.0.0/16"
		sp := ""
		if v, ok := msg["Pool"]; ok && v.(string) != "" {
			pl = v.(string)
		}
		if v, ok := msg["SubPool"]; ok && v.(string) != "" {
			sp = v.(string)
		}
		pid := fmt.Sprintf("%s/%s", as, pl)
		if sp != "" {
			pid = fmt.Sprintf("%s/%s", pid, sp)
		}
		return map[string]interface{}{
			"PoolID": pid,
			"Pool":   pl,
			"Data":   map[string]string{"DNS": "8.8.8.8"},
		}
	})

	handle(t, mux, "ReleasePool", func(msg map[string]interface{}) interface{} {
		if _, ok := msg["PoolID"]; !ok {
			t.Fatalf("Missing PoolID in Release request")
		}
		return map[string]interface{}{}
	})

	handle(t, mux, "RequestAddress", func(msg map[string]interface{}) interface{} {
		if _, ok := msg["PoolID"]; !ok {
			t.Fatalf("Missing PoolID in address request")
		}
		prefAddr := ""
		if v, ok := msg["Address"]; ok {
			prefAddr = v.(string)
		}
		ip := prefAddr
		if ip == "" {
			ip = "172.20.0.34"
		}
		ip = fmt.Sprintf("%s/16", ip)
		dnsList := []string{"172.20.0.1", "172.20.0.2"}
		dnsSearchList := []string{"domain1", "domain2"}
		return map[string]interface{}{
			"Address":          ip,
			"DNSServers":       dnsList,
			"DNSSearchDomains": dnsSearchList,
		}
	})

	handle(t, mux, "ReleaseAddress", func(msg map[string]interface{}) interface{} {
		if _, ok := msg["PoolID"]; !ok {
			t.Fatalf("Missing PoolID in address request")
		}
		if _, ok := msg["Address"]; !ok {
			t.Fatalf("Missing Address in release address request")
		}
		return map[string]interface{}{}
	})

	p, err := plugins.Get(plugin, ipamapi.PluginEndpointType)
	if err != nil {
		t.Fatal(err)
	}

	d := newAllocator(plugin, p.Client)

	return d, nil
}

func TestRemoteDriver(t *testing.T) {
	d, _ := getRemoteAllocator("test-ipam-driver", t)

	l, g, err := d.(*allocator).GetDefaultAddressSpaces()
	if err != nil {
		t.Fatal(err)
	}
	if l != "white" || g != "blue" {
		t.Fatalf("Unexpected default local/global address spaces: %s, %s", l, g)
	}

	// Request any pool
	poolID, pool, _, err := d.RequestPool("white", "", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if poolID != "white/172.18.0.0/16" {
		t.Fatalf("Unexpected pool id: %s", poolID)
	}
	if pool == nil || pool.String() != "172.18.0.0/16" {
		t.Fatalf("Unexpected pool: %s", pool)
	}

	// Request specific pool
	poolID2, pool2, ops, err := d.RequestPool("white", "172.20.0.0/16", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	if poolID2 != "white/172.20.0.0/16" {
		t.Fatalf("Unexpected pool id: %s", poolID2)
	}
	if pool2 == nil || pool2.String() != "172.20.0.0/16" {
		t.Fatalf("Unexpected pool: %s", pool2)
	}
	if dns, ok := ops["DNS"]; !ok || dns != "8.8.8.8" {
		t.Fatalf("Missing options")
	}

	// Request specific pool and subpool
	poolID3, pool3, _, err := d.RequestPool("white", "172.20.0.0/16", "172.20.3.0/24" /*nil*/, map[string]string{"culo": "yes"}, false)
	if err != nil {
		t.Fatal(err)
	}
	if poolID3 != "white/172.20.0.0/16/172.20.3.0/24" {
		t.Fatalf("Unexpected pool id: %s", poolID3)
	}
	if pool3 == nil || pool3.String() != "172.20.0.0/16" {
		t.Fatalf("Unexpected pool: %s", pool3)
	}

	// Request any address
	addr, _, dnsList, dnsSearchDomains, err := d.RequestAddress(poolID2, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr == nil || addr.String() != "172.20.0.34/16" {
		t.Fatalf("Unexpected address: %s", addr)
	}
	if dnsList == nil || len(dnsList) != 2 || dnsList[0] != "172.20.0.1" || dnsList[1] != "172.20.0.2" {
		t.Fatalf("Unexpected DNS list: %+v", dnsList)
	} else {
		t.Logf("Expected DNS list: %+v", dnsList)
	}
	if dnsSearchDomains == nil || len(dnsSearchDomains) != 2 || dnsSearchDomains[0] != "domain1" || dnsSearchDomains[1] != "domain2" {
		t.Fatalf("Unexpected DNS Search Domains List: %+v", dnsSearchDomains)
	} else {
		t.Logf("Expected DNS Search Domains List: %+v", dnsSearchDomains)
	}

	// Request specific address
	addr2, _, _, _, err := d.RequestAddress(poolID2, net.ParseIP("172.20.1.45"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if addr2 == nil || addr2.String() != "172.20.1.45/16" {
		t.Fatalf("Unexpected address: %s", addr2)
	}

	// Release address
	err = d.ReleaseAddress(poolID, net.ParseIP("172.18.1.45"))
	if err != nil {
		t.Fatal(err)
	}
}

/*
func randomLocalStore() (datastore.DataStore, error) {
	tmp, err := ioutil.TempFile("", "libnetwork-ipamremote")
	if err != nil {
		return nil, fmt.Errorf("Error creating temp file: %v", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("Error closing temp file: %v", err)
	}
	return datastore.NewDataStore(datastore.LocalScope, &datastore.ScopeCfg{
		Client: datastore.ScopeClientCfg{
			Provider: "boltdb",
			Address:  defaultPrefix + tmp.Name(),
			Config: &store.Config{
				Bucket:            "libnetwork",
				ConnectionTimeout: 3 * time.Second,
			},
		},
	})
}
*/
func TestRetrieveFromStore(t *testing.T) {
	plugin := "test-ipam-driver-retrieve"

	num := 200
	/*
		ds, err := randomLocalStore()
		if err != nil {
			t.Fatal(err)
		}
	*/
	rd, err := getRemoteAllocator(plugin, t)
	if err != nil {
		t.Fatal(err)
	}

	localAS, globalAS, err := rd.(*allocator).GetDefaultAddressSpaces()
	if err != nil {
		t.Fatal(err)
	}

	if localAS != "white" || globalAS != "blue" {
		t.Fatalf("Unexpected default local/global address spaces: %s, %s", localAS, globalAS)
	}

	pid, _, _, err := rd.RequestPool(localAS, "172.25.0.0/16", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < num; i++ {
		if _, _, _, _, err := rd.RequestAddress(pid, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Restore
	rd1, err := getRemoteAllocator(plugin, t)
	if err != nil {
		t.Fatal(err)
	}
	rd1.(*allocator).refresh(localAS)
	db := rd.(*allocator).DumpDatabase()
	db1 := rd1.(*allocator).DumpDatabase()
	if db != db1 {
		t.Fatalf("Unexpected db change.\nExpected:%s\nGot:%s", db, db1)
	}
	checkDBEquality(rd, rd1, localAS, t)
	pid, _, _, err = rd1.RequestPool(localAS, "172.25.0.0/16", "172.25.1.0/24", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < num/2; i++ {
		if _, _, _, _, err := rd1.RequestAddress(pid, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Restore
	rd2, err := getRemoteAllocator(plugin, t)
	if err != nil {
		t.Fatal(err)
	}
	rd2.(*allocator).refresh(localAS)
	checkDBEquality(rd1, rd2, localAS, t)
	pid, _, _, err = rd2.RequestPool(localAS, "172.25.0.0/16", "172.25.2.0/24", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < num/2; i++ {
		if _, _, _, _, err := rd2.RequestAddress(pid, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Restore
	rd3, err := getRemoteAllocator(plugin, t)
	if err != nil {
		t.Fatal(err)
	}
	rd3.(*allocator).refresh(localAS)
	checkDBEquality(rd2, rd3, localAS, t)
	pid, _, _, err = rd3.RequestPool(localAS, "172.26.0.0/16", "", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < num/2; i++ {
		if _, _, _, _, err := rd3.RequestAddress(pid, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	// Restore
	rd4, err := getRemoteAllocator(plugin, t)
	if err != nil {
		t.Fatal(err)
	}
	rd4.(*allocator).refresh(localAS)
	checkDBEquality(rd3, rd4, localAS, t)
}

func checkDBEquality(rd1, rd2 ipamapi.Ipam, localAS string, t *testing.T) {
	for k, cnf1 := range rd1.(*allocator).addrSpaces[localAS].subnets {
		cnf2 := rd2.(*allocator).addrSpaces[localAS].subnets[k]
		if cnf1.String() != cnf2.String() {
			t.Fatalf("%s\n%s", cnf1, cnf2)
		}
		if cnf1.(*allocator).Range == nil {
			rd2.retrieveBitmask(k, cnf1.(*allocator).Pool)
		}
	}

	for k, bm1 := range rd1.(*allocator).addresses {
		bm2 := rd2.(*allocator).addresses[k]
		if bm1.String() != bm2.String() {
			t.Fatalf("%s\n%s", bm1, bm2)
		}
	}
}
