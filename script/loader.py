'''
Takes network.json, builds a graph, and computes the
reachability matrix.
'''

import json
import sys
import csv
import argparse

class Model:
    # wrapper class for the network model

    def __init__(self, data):
        self.data = data
        self.net = data["network"]
        self.hosts = {h["id"]: h for h in self.net["hosts"]}
        self.zones = {z["id"]: z for z in self.net["zones"]}
        self.firewall = self.net.get("firewall_rules", [])
        self.trusts = self.net.get("trust_relations", [])
        self.flows = self.net.get("data_flows", [])
        self.goals = data.get("goals", [])
        self.mitigations = data.get("mitigations", [])
    
    # get the zone of a host
    def zone_of(self, host_id):
        return self.hosts[host_id]["zone"]

    # given a zone id, return whether it is trusted or not
    def zone_trusted(self, zone_id):
        return self.zones[zone_id].get("trusted", False)

    def all_cves(self):
        # return a set of all CVEs in the model
        cves = set()
        for h in self.hosts.values():
            for v in h.get("vulnerabilities", []):
                cves.add(v["cve"])
        return cves


def main():
    # parse command line arguments
    ap = argparse.ArgumentParser(description="LOADER — validate & model the network")
    ap.add_argument("input", help="path to network.json")
    ap.add_argument("--emit-reachability", metavar="CSV")
    ap.add_argument("--emit-dfd", metavar="PNG")

    args = ap.parse_args()

    try:
        # try loading the input file
        data = load(args.input)
        validate(data)
    
    except ValidationError as e:
        print("REJECTED:", e, file=sys.stderr)
        sys.exit(1)

    model = Model(data) # build the model
    print(f"OK: {len(model.hosts)} hosts, {len(model.zones)} zones, "
          f"{len(model.all_cves())} vulnerabilities, {len(model.goals)} goals.")

if __name__ == '__main__':
    main()

