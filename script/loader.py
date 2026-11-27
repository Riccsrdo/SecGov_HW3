'''
Takes network.json, builds a graph, and computes the
reachability matrix.
'''

import json
import sys
import csv
import argparse

def load(path):
    """Read and JSON-parse the file. Fails loudly on bad JSON."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except FileNotFoundError:
        raise ValidationError(f"Input file not found: {path}")
    except json.JSONDecodeError as e:
        raise ValidationError(f"Malformed JSON: {e}")


def validate(data):
    """
    Structural + cross-reference checks. We collect ALL problems and
    raise them together, so the user sees every error at once rather
    than fixing them one run at a time.
    """
    errors = []

    net = data.get("network")
    if not isinstance(net, dict):
        raise ValidationError("Top-level 'network' object is missing.")

    zones = {z["id"] for z in net.get("zones", []) if "id" in z}
    if not zones:
        errors.append("No zones defined.")

    hosts = net.get("hosts", [])
    host_ids = set()
    # 2a. Per-host structural checks
    for i, h in enumerate(hosts):
        hid = h.get("id")
        if not hid:
            errors.append(f"Host #{i} has no 'id'.")
            continue
        if hid in host_ids:
            errors.append(f"Duplicate host id: {hid}")
        host_ids.add(hid)
        if h.get("zone") not in zones:
            errors.append(f"{hid}: zone '{h.get('zone')}' is not a declared zone.")
        service_names = {s.get("name") for s in h.get("services", [])}
        # Every vulnerability must reference a service that exists on the host.
        for v in h.get("vulnerabilities", []):
            if v.get("service") not in service_names:
                errors.append(
                    f"{hid}: vulnerability {v.get('cve')} references service "
                    f"'{v.get('service')}' not present on the host."
                )
        # Misconfigurations likewise reference a service.
        for mc in h.get("misconfigurations", []):
            if mc.get("service") not in service_names:
                errors.append(
                    f"{hid}: misconfig {mc.get('id')} references unknown "
                    f"service '{mc.get('service')}'."
                )

    # 2b. Firewall rules must reference real zones/hosts.
    for r in net.get("firewall_rules", []):
        for key in ("src_zone", "dst_zone"):
            if r.get(key) not in zones:
                errors.append(f"Firewall rule uses unknown {key}: {r.get(key)}")
        for key in ("src_host", "dst_host"):
            hv = r.get(key)
            if hv not in ("*", None) and hv not in host_ids:
                errors.append(f"Firewall rule references unknown {key}: {hv}")

    # 2c. Trust relations must reference real hosts.
    for t in net.get("trust_relations", []):
        for key in ("from_host", "to_host"):
            if t.get(key) not in host_ids:
                errors.append(f"Trust {t.get('id')} references unknown host {t.get(key)}")

    # 2d. Goals and mitigation targets must reference real hosts/CVEs.
    all_cves = {v["cve"] for h in hosts for v in h.get("vulnerabilities", [])}
    for g in data.get("goals", []):
        if g.get("host") not in host_ids:
            errors.append(f"Goal {g.get('id')} references unknown host {g.get('host')}")
    for m in data.get("mitigations", []):
        for tgt in m.get("targets", []):
            # patch targets look like [host, cve]; misconfig targets are "MCx" strings.
            if isinstance(tgt, list) and len(tgt) == 2:
                host, cve = tgt
                if host not in host_ids:
                    errors.append(f"Mitigation {m['id']} targets unknown host {host}")
                if cve not in all_cves:
                    errors.append(f"Mitigation {m['id']} targets unknown CVE {cve}")

    if errors:
        raise ValidationError("Validation failed:\n  - " + "\n  - ".join(errors))
    return True


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


def _rule_matches(rule, src_zone, src_host, dst_zone, dst_host):
    """A firewall rule applies if zones match and host is '*' or exact."""
    if rule["src_zone"] != src_zone or rule["dst_zone"] != dst_zone:
        return False
    if rule["src_host"] not in ("*", src_host):
        return False
    if rule["dst_host"] not in ("*", dst_host):
        return False
    return rule.get("action") == "allow"

def reachability(model):
    # returns {src_host: {dst_host: set(ports)}}
    hosts = list(model.hosts)
    matrix = {src: {dst: set() for dst in hosts} for src in hosts}
    matrix["ATTACKER"] = {dst: set() for dst in hosts} # add attacker row

    # from Attacker to Internal hosts, rules where src_zone is internet
    for dst in hosts:
        dz = model.zone_of(dst)
        for r in model.firewall:
            if r["src_zone"] == "internet" and _rule_matches(r, "internet", "*", dz, dst):
                matrix["ATTACKER"][dst].update(r["ports"])

    # host to host reachability, check firewall rules
    for src in hosts:
        sz = model.zone_of(src)
        for dst in hosts:
            if src == dst:
                continue
            dz = model.zone_of(dst)
            for r in model.firewall:
                if _rule_matches(r, sz, src, dz, dst):
                    matrix[src][dst].update(r["ports"])
    return matrix

def write_reachability_csv(matrix, filename):
    hosts = [h for h in matrix if h!= "ATTACKER"]
    order = ["ATTACKER"] + sorted(hosts) # sort hosts for consistent output
    cols = sorted(hosts)
    with open(filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["src\\dst"] + cols)
        for src in order:
            row = [src]
            for dst in cols:
                ports = matrix.get(src, {}).get(dst, set()) # get the set of ports
                row.append("|".join(map(str, sorted(ports))) if ports else "") # join ports with |, or empty string if no ports
            writer.writerow(row)

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

    if args.emit_reachability:
        write_reachability_csv(reachability(model), args.emit_reachability)
        print("Reachability matrix ->", args.emit_reachability)

if __name__ == '__main__':
    main()

