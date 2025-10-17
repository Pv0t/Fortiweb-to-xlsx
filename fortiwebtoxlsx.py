import json
import re
import sys
import shlex
import pandas as pd
import ipaddress
import argparse

def parse_config(lines):
    result = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("config "):
            section_name = line.replace("config ", "").strip()
            sub_lines = []
            depth = 1
            i += 1
            while i < len(lines) and depth > 0:
                l = lines[i].strip()
                if l.startswith("config "):
                    depth += 1
                elif l == "end":
                    depth -= 1
                    if depth == 0:
                        i += 1
                        break
                sub_lines.append(lines[i])
                i += 1
            parsed_sub = parse_config(sub_lines)
            result.append({section_name: parsed_sub})
            continue

        elif line.startswith("edit "):
            obj_id = line.replace("edit ", "").strip().strip('"')
            obj = {"id": obj_id}
            sub_lines = []
            nested_depth = 0
            i += 1
            while i < len(lines):
                l = lines[i].strip()
                if l.startswith("config "):
                    nested_depth += 1
                elif l == "end":
                    nested_depth -= 1
                if l == "next" and nested_depth == 0:
                    i += 1
                    break
                sub_lines.append(lines[i])
                i += 1
            j = 0
            while j < len(sub_lines):
                l = sub_lines[j].strip()
                if l.startswith("set "):
                    m = re.match(r"set (\S+) (.*)", l)
                    if m:
                        key, value_str = m.groups()
                        try:
                            values = shlex.split(value_str)
                        except ValueError:
                            values = value_str.split()
                        if len(values) == 1:
                            obj[key] = values[0]
                        elif len(values) > 1:
                            obj[key] = values
                    j += 1
                elif l.startswith("config "):
                    section_name = l.replace("config ", "").strip()
                    nested_lines = []
                    depth = 1
                    j += 1
                    while j < len(sub_lines) and depth > 0:
                        nl = sub_lines[j].strip()
                        if nl.startswith("config "):
                            depth += 1
                        elif nl == "end":
                            depth -= 1
                            if depth == 0:
                                j += 1
                                break
                        nested_lines.append(sub_lines[j])
                        j += 1
                    parsed_nested = parse_config(nested_lines)
                    if parsed_nested:
                        obj[section_name] = parsed_nested
                else:
                    j += 1
            result.append(obj)
            continue
        else:
            i += 1
    return result

def build_id_map(parsed):
    id_map = {}
    def recurse(item):
        if isinstance(item, dict):
            id_val = item.get('id')
            if id_val:
                id_map[id_val] = item
            for v in item.values():
                recurse(v)
        elif isinstance(item, list):
            for sub in item:
                recurse(sub)
    recurse(parsed)
    return id_map

def enrich_policies(parsed, id_map):
    policies_list = []
    for section in parsed:
        if "server-policy policy" in section:
            policies = section["server-policy policy"]
            break
    else:
        policies = []
    for pol in policies:
        enriched = dict(pol)
        pool_id = pol.get("server-pool")
        if pool_id and isinstance(pool_id, str):
            full_pool = id_map.get(pool_id)
            if full_pool:
                enriched["server-pool"] = full_pool
                persistence_id = full_pool.get("persistence")
                if persistence_id and isinstance(persistence_id, str):
                    full_persistence = id_map.get(persistence_id)
                    if full_persistence:
                        full_pool["persistence"] = full_persistence
                health_id = full_pool.get("health")
                if health_id and isinstance(health_id, str):
                    full_health = id_map.get(health_id)
                    if full_health:
                        full_pool["health"] = full_health
        host_id = pol.get("allow-hosts")
        if host_id and isinstance(host_id, str):
            full_host = id_map.get(host_id)
            if full_host:
                enriched["allow-hosts"] = full_host
        profile_id = pol.get("web-protection-profile")
        if profile_id and isinstance(profile_id, str):
            full_profile = id_map.get(profile_id)
            if full_profile:
                enriched["web-protection-profile"] = full_profile
        vserver_id = pol.get("vserver")
        if vserver_id and isinstance(vserver_id, str):
            full_vserver = id_map.get(vserver_id)
            if full_vserver:
                enriched["vserver"] = full_vserver
                if "vip-list" in full_vserver:
                    for vip_item in full_vserver["vip-list"]:
                        vip_name = vip_item.get("vip")
                        if vip_name and isinstance(vip_name, str):
                            full_vip = id_map.get(vip_name)
                            if full_vip:
                                vip_item["vip"] = full_vip        
        xff_rule_id = pol.get("x-forwarded-for-rule")
        if xff_rule_id and isinstance(xff_rule_id, str):
            full_xff_rule = id_map.get(xff_rule_id)
            if full_xff_rule:
                enriched["x-forwarded-for-rule"] = full_xff_rule
        if "http-content-routing-list" in enriched:
            for routing_item in enriched["http-content-routing-list"]:
                policy_name = routing_item.get("content-routing-policy-name")
                if policy_name and isinstance(policy_name, str):
                    full_policy = id_map.get(policy_name)
                    if full_policy:
                        routing_item["content-routing-policy"] = full_policy
                        cr_pool_id = full_policy.get("server-pool")
                        if cr_pool_id and isinstance(cr_pool_id, str):
                            full_cr_pool = id_map.get(cr_pool_id)
                            if full_cr_pool:
                                full_policy["server-pool"] = full_cr_pool
                                persistence_id = full_cr_pool.get("persistence")
                                if persistence_id and isinstance(persistence_id, str):
                                    full_persistence = id_map.get(persistence_id)
                                    if full_persistence:
                                        full_cr_pool["persistence"] = full_persistence
                                health_id = full_cr_pool.get("health")
                                if health_id and isinstance(health_id, str):
                                    full_health = id_map.get(health_id)
                                    if full_health:
                                        full_cr_pool["health"] = full_health
        policies_list.append(enriched)
    return {"policies": policies_list}

def get_server_ips(pool):
    server_ips = []
    for key in ['member-list', 'server-list', 'pserver-list']:
        if key in pool:
            ip_key = 'server-ip' if key == 'member-list' else 'ip'
            for item in pool[key]:
                ip = item.get(ip_key, '')
                if ip:
                    server_ips.append(ip)
    return server_ips

def create_excel(final, excel_file):
    policies = final.get('policies', [])
    data = []
    for idx, policy in enumerate(policies, start=1):
        policy_name = policy.get('id', '')
        protected_hostnames = []
        allow_hosts = policy.get('allow-hosts', {})
        if 'host-list' in allow_hosts:
            for host_item in allow_hosts['host-list']:
                host = host_item.get('host', '')
                if host:
                    parts = host.split(':', 1)
                    check_part = parts[0]
                    try:
                        ipaddress.ip_address(check_part)
                    except ValueError:
                        protected_hostnames.append(host)
        protected_hostname_str = ', '.join(protected_hostnames) or 'None'
        vip_name = ''
        vip = ''
        if 'vserver' in policy and 'vip-list' in policy['vserver'] and policy['vserver']['vip-list']:
            first_vip = policy['vserver']['vip-list'][0].get('vip', {})
            vip_name = first_vip.get('id', '') or 'None'
            vip = first_vip.get('vip', '') or 'None'

        server_pool_obj = policy.get('server-pool', {})
        server_pool_name = server_pool_obj.get('id', '') 
        server_ips = get_server_ips(server_pool_obj)
        server_pool_str = server_pool_name
        if server_ips:
            server_pool_str += f" ({', '.join(server_ips)})"
        if not server_pool_str:
            server_pool_str = 'None'
        deployment_mode_raw = policy.get('deployment-mode', '')
        deployment_mode = "Content Routing" if deployment_mode_raw == "http-content-routing" else "Single/Balanced Server"
        content_routing_policy = ''
        if 'http-content-routing-list' in policy:
            crps = []
            for item in policy['http-content-routing-list']:
                if 'content-routing-policy' in item:
                    crp = item['content-routing-policy']
                    crp_name = crp.get('id', '')
                    server_pool_obj = crp.get('server-pool', {})
                    server_ips = get_server_ips(server_pool_obj)
                    if server_ips:
                        ips_str = ', '.join(server_ips)
                        crps.append(f"{crp_name} ({ips_str})")
                    else:
                        crps.append(crp_name)
            content_routing_policy = ', '.join(crps)
        if not content_routing_policy:
            content_routing_policy = 'None'
        load_balancing_algorithm = policy.get('server-pool', {}).get('lb-algo', 'Round Robin')
        if load_balancing_algorithm == 'least-connections':
            load_balancing_algorithm = 'Least Connections'
        if load_balancing_algorithm == 'weighted-round-robin':
            load_balancing_algorithm = 'Weighted Round Robin'
        if load_balancing_algorithm == 'least-response-time':
            load_balancing_algorithm = 'Least Response Time'
        if load_balancing_algorithm == 'uri-hash':
            load_balancing_algorithm = 'URI Hash'
        if load_balancing_algorithm == 'full-uri-hash':
            load_balancing_algorithm = 'Full URI Hash'
        if load_balancing_algorithm == 'host-hash':
            load_balancing_algorithm = 'Host Hash'
        if load_balancing_algorithm == 'host-domain-hash':
            load_balancing_algorithm = 'Host Domain Hash'
        if load_balancing_algorithm == 'src-ip-hash':
            load_balancing_algorithm = 'Source IP Hash'
        if load_balancing_algorithm == 'probabilistic-weighted-least-response-time':
            load_balancing_algorithm = 'Probabilistic Weighted Least Response Time'
        health_types = set()
        if 'server-pool' in policy and policy['server-pool']:
            health = policy['server-pool'].get('health')
            if isinstance(health, dict) and 'type' in health:
                health_type = health.get('type')
                if health_type:
                    health_types.add(health_type.upper())
        if 'http-content-routing-list' in policy:
            for item in policy['http-content-routing-list']:
                if 'content-routing-policy' in item:
                    crp = item['content-routing-policy']
                    if 'server-pool' in crp and crp['server-pool']:
                        health = crp['server-pool'].get('health')
                        if isinstance(health, dict) and 'type' in health:
                            health_type = health.get('type')
                            if health_type:
                                health_types.add(health_type.upper())
        health_check = ', '.join(sorted(health_types)) if health_types else 'None'
        certificate = policy.get('certificate', 'None')
        persistence_types = set()
        if 'server-pool' in policy and policy['server-pool']:
            persistence = policy['server-pool'].get('persistence')
            if isinstance(persistence, dict) and 'type' in persistence:
                persistence_type = persistence.get('type')
                if persistence_type == 'persistent-cookie':
                    persistence_type = 'Persistent Cookie'
                if persistence_type == 'http-header':
                    persistence_type = 'HTTP Header'
                if persistence_type == 'ssl-session-id':
                    persistence_type = 'SSL Session ID'
                if persistence_type:
                    persistence_types.add(persistence_type)
        if 'http-content-routing-list' in policy:
            for item in policy['http-content-routing-list']:
                if 'content-routing-policy' in item:
                    crp = item['content-routing-policy']
                    if 'server-pool' in crp and crp['server-pool']:
                        persistence = crp['server-pool'].get('persistence')
                        if isinstance(persistence, dict) and 'type' in persistence:
                            persistence_type = persistence.get('type')
                            if persistence_type:
                                persistence_types.add(persistence_type)
        persistence_str = ', '.join(sorted(persistence_types)) if persistence_types else 'None'
        xff_name = policy.get('web-protection-profile', {}).get('x-forwarded-for-rule', 'None')
        if xff_name == 'client-ip-header':
            xff_name = 'X-Forwarded-For'
        if xff_name == "client-ip-header_new":
            xff_name = "X-Forwarded-For"
        if xff_name == "client-ip_x-forwaeded-proto":
            xff_name = "X-Forwarded-For"
        monitor_mode = 'Enabled' if policy.get('monitor-mode') == 'enable' else 'Disabled'
        row = {
            'Entry': idx,
            'Policy Name': policy_name,
            'Protected Hostname': protected_hostname_str,
            'VIP Name': vip_name,
            'VIP': vip,
            'Server Pool': server_pool_str,
            'Deployment Mode': deployment_mode,
            'Content Routing Policy': content_routing_policy,
            'Monitor Mode': monitor_mode,
            'Load Balancing Algorithm': load_balancing_algorithm,
            'Health Check': health_check,
            'Certificate': certificate,
            'Persistence': persistence_str,
            'X-Forwarded-For/X-Real-IP': xff_name,
        }
        data.append(row)
    df = pd.DataFrame(data)
    df.to_excel(excel_file, index=False)

def fortiweb_conf_to_json(conf_file, output_base, produce_json, produce_excel):
    with open(conf_file, "r", encoding="latin-1") as f:
        lines = [line.rstrip("\n") for line in f]
    parsed = parse_config(lines)
    id_map = build_id_map(parsed)
    final = enrich_policies(parsed, id_map)
    if produce_json:
        json_file = f"{output_base}.json"
        with open(json_file, "w", encoding="utf-8") as f:
            json.dump(final, f, indent=4, ensure_ascii=False)
        print(f"File JSON: {json_file}")
    if produce_excel:
        excel_file = f"{output_base}.xlsx"
        create_excel(final, excel_file)
        print(f"File Excel: {excel_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="=================================")
    parser.add_argument("conf_file", help="Configurazione del file di FortiWeb")
    parser.add_argument("output_base", help="Nome del file in output (senza l'estensione)")
    parser.add_argument("--json", action="store_true", help="Produce il file in JSON (viene fatto in default se non specificato)")
    parser.add_argument("--excel", action="store_true", help="Produce il file in Excel (viene fatto in default se non specificato)")
    args = parser.parse_args()

    produce_json = args.json
    produce_excel = args.excel
    if not (produce_json or produce_excel):
        produce_json = True
        produce_excel = True
    fortiweb_conf_to_json(args.conf_file, args.output_base, produce_json, produce_excel)
