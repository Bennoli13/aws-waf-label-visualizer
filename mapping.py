import json
import re
import os

# Load AWS-managed rules label mapping
managed_label_map_path = os.path.join("aws-managedrules-labels.json")
if os.path.exists(managed_label_map_path):
    with open(managed_label_map_path) as f:
        MANAGED_LABEL = json.load(f)
else:
    MANAGED_LABEL = {}

def get_children(label, items):
    return [item for item in items if item != label and item.startswith(label + ":")]

def main(waf_config,mmd_path):
    rules = waf_config.get("Rules", [])
    label_relations = {}
    rule_actions = {}

    # Track which rule has which action
    for rule in rules:
        rule_name = rule.get("Name")
        action_dict = rule.get("Action", {})
        action_type = next(iter(action_dict), "Unknown")
        rule_actions[rule_name] = action_type

        # Label producers
        for label in rule.get("RuleLabels", []):
            label_name = label["Name"]
            label_relations.setdefault(label_name, {"producers": [], "consumers": []})
            label_relations[label_name]["producers"].append(rule_name)

        # Label consumers
        def find_label_consumers(statement):
            if not isinstance(statement, dict):
                return
            if "LabelMatchStatement" in statement:
                key = statement["LabelMatchStatement"]["Key"]
                label_relations.setdefault(key, {"producers": [], "consumers": []})
                label_relations[key]["consumers"].append(rule_name)
            for v in statement.values():
                if isinstance(v, dict):
                    find_label_consumers(v)
                elif isinstance(v, list):
                    for item in v:
                        find_label_consumers(item)

        find_label_consumers(rule.get("Statement", {}))

    # Write Mermaid diagram
    with open(mmd_path, "w") as f:
        f.write("%% Auto-generated WAF rule-label map\n\n")
        for label, rel in label_relations.items():
            f.write(f"graph TD\n")
            f.write(f"  subgraph Label: {label}\n")
            if get_children(label, rel["consumers"]):
                namespace = f"namespace: {get_children(label, rel['consumers'])}"
            for producer in set(rel["producers"]):
                f.write(f"    {producer} -->|produces| {label}\n") 
                if namespace:
                    f.write(f"    {label} -->|namespace| {namespace}\n")
            for consumer in set(rel["consumers"]):
                action = rule_actions.get(consumer, "Unknown")
                f.write(f"    {label} -->|consumed by| {consumer}[\"{consumer}\"] -->|action|{action}\n")
            f.write("  end\n\n")

def find_label_relationships(rules):
    label_producers = {}
    label_consumers = {}

    for rule in rules:
        name = rule["Name"]

        # 1. RuleLabels (manual labels)
        for label in rule.get("RuleLabels", []):
            label_name = label["Name"]
            label_producers.setdefault(label_name, []).append(name)

        # 2. ManagedRuleGroup labels
        statement = rule.get("Statement", {})
        managed = statement.get("ManagedRuleGroupStatement")
        if managed:
            vendor = managed.get("VendorName", "").lower()
            group = managed.get("Name")
            overrides = managed.get("RuleActionOverrides")

            if overrides is not None:
                for override in overrides:
                    rule_name = override.get("Name")
                    if rule_name:
                        label = f"awswaf:managed:{vendor}:*:{rule_name}"
                        label_producers.setdefault(label, []).append(name)
            else:
                # No overrides — check static label map
                managed_labels = MANAGED_LABEL.get(group)
                if managed_labels:
                    for rule_name in managed_labels:
                        label = f"awswaf:managed:{vendor}:*:{rule_name}"
                        label_producers.setdefault(label, []).append(name)

        # 3. Consumers via LabelMatchStatement
        def search_labels(stmt):
            if isinstance(stmt, dict):
                if "LabelMatchStatement" in stmt:
                    key = stmt["LabelMatchStatement"]["Key"]
                    label_consumers.setdefault(key, []).append(name)
                for v in stmt.values():
                    search_labels(v)
            elif isinstance(stmt, list):
                for item in stmt:
                    search_labels(item)

        search_labels(statement)

    return label_producers, label_consumers


def build_relationship(rule_name, rules, producers, consumers, visited=None):
    if visited is None:
        visited = set()
    if rule_name in visited:
        return {}
    visited.add(rule_name)

    result = {
        "produce": {},
        "consume": {},
        "action": None
    }

    rule_def = next((r for r in rules if r["Name"] == rule_name), None)
    if not rule_def:
        return result

    action_key = list(rule_def.get("Action", {}).keys())[0] if rule_def.get("Action") else None
    result["action"] = action_key

    # Start with explicit RuleLabels
    produces = [lbl["Name"] for lbl in rule_def.get("RuleLabels", [])]

    # Add simulated labels from managed rules
    statement = rule_def.get("Statement", {})
    managed = statement.get("ManagedRuleGroupStatement")
    if managed:
        vendor = managed.get("VendorName", "").lower()
        group = managed.get("Name", "")

        # Add overrides if present
        overrides = managed.get("RuleActionOverrides", [])
        if overrides:
            for override in overrides:
                rule = override.get("Name")
                if vendor and rule:
                    simulated_label = f"awswaf:managed:{vendor}:*:{rule}"
                    produces.append(simulated_label)
        else:
            rule_names = MANAGED_LABEL.get(group, [])
            for rule in rule_names:
                simulated_label = f"awswaf:managed:{vendor}:*:{rule}"
                produces.append(simulated_label)
 
    # Collect consumed labels
    consumes = []

    def collect_consumes(stmt):
        if isinstance(stmt, dict):
            if "LabelMatchStatement" in stmt:
                key = stmt["LabelMatchStatement"]["Key"]
                consumes.append(key)
            for v in stmt.values():
                collect_consumes(v)
        elif isinstance(stmt, list):
            for item in stmt:
                collect_consumes(item)

    collect_consumes(statement)

    # Build produce relationships
    for label in produces:
        result["produce"][label] = []
        for lbl_key, rel_rules in consumers.items():
            if lbl_key.split(":")[-1] == label.split(":")[-1]:
                for rel_rule in rel_rules:
                    sub_map = build_relationship(rel_rule, rules, producers, consumers, visited.copy())
                    result["produce"][label].append({rel_rule: sub_map})

    # Build consume relationships
    for label in consumes:
        result["consume"][label] = []
        for lbl_key, rel_rules in producers.items():
            if lbl_key.split(":")[-1] == label.split(":")[-1]:
                for rel_rule in rel_rules:
                    sub_map = build_relationship(rel_rule, rules, producers, consumers, visited.copy())
                    rel_rule_def = next((r for r in rules if r["Name"] == rel_rule), {})
                    rel_action = list(rel_rule_def.get("Action", {}).keys())[0] if rel_rule_def.get("Action") else None
                    result["consume"][label].append({
                        rel_rule: sub_map,
                        "action": rel_action
                    })

    return result


def generate_mermaid_from_relationship(relationship, root_rule_name=None):
    mermaid = ["graph TD"]
    visited_rules = set()
    added_lines = set()

    def add_line(line):
        if line not in added_lines:
            mermaid.append(f"    {line}")
            added_lines.add(line)

    def traverse(current_rule, rel):
        rule_id = (current_rule, json.dumps(rel, sort_keys=True))
        if rule_id in visited_rules:
            return
        visited_rules.add(rule_id)

        # Attach action of the current rule itself
        if rel.get("action"):
            add_line(f'{current_rule} -->|action| {rel["action"]}')

        # --- Produced labels
        for label, consumers in rel.get("produce", {}).items():
            label_node = f"Label:{label}"
            add_line(f'{current_rule} -->|produces| {label_node}')
            for consumer in consumers:
                for consumer_rule, sub_rel in consumer.items():
                    if consumer_rule == "action":
                        continue
                    add_line(f'{label_node} -->|consume| {consumer_rule}')
                    traverse(consumer_rule, sub_rel)

        # --- Consumed labels
        for label, producers in rel.get("consume", {}).items():
            label_node = f"Label:{label}"
            for producer in producers:
                for producer_rule, sub_rel in producer.items():
                    if producer_rule == "action":
                        continue
                    add_line(f'{producer_rule} -->|produces| {label_node}')
                    add_line(f'{label_node} -->|consume| {current_rule}')
                    traverse(producer_rule, sub_rel)

    if root_rule_name:
        traverse(root_rule_name, relationship)
    else:
        for label, producers in relationship.get("produce", {}).items():
            for item in producers:
                for rule_name, sub_rel in item.items():
                    traverse(rule_name, sub_rel)

    return "\n".join(mermaid)


def clean_node(node):
        cleaned = {}

        # Clean 'produce'
        if "produce" in node:
            cleaned_produce = {}
            for label, rules in node["produce"].items():
                cleaned_rules = []
                for rule in rules:
                    for rule_name, rule_data in rule.items():
                        cleaned_rule_data = clean_node(rule_data)
                        if cleaned_rule_data.get("produce") or cleaned_rule_data.get("consume"):
                            cleaned_rules.append({rule_name: cleaned_rule_data})
                if cleaned_rules:
                    cleaned_produce[label] = cleaned_rules
            if cleaned_produce:
                cleaned["produce"] = cleaned_produce

        # Clean 'consume'
        if "consume" in node:
            cleaned_consume = {}
            for label, rules in node["consume"].items():
                cleaned_rules = []
                for rule in rules:
                    cleaned_rule = {}
                    for k, v in rule.items():
                        if k == "action":
                            cleaned_rule["action"] = v
                        else:
                            cleaned_rule[k] = clean_node(v)
                    cleaned_rules.append(cleaned_rule)
                if cleaned_rules:
                    cleaned_consume[label] = cleaned_rules
            if cleaned_consume:
                cleaned["consume"] = cleaned_consume

        return cleaned

def convert_to_vis_graph(data):
    nodes = set()
    edges = []

    def add_node(node_id, label=None):
        if node_id not in nodes:
            nodes.add(node_id)
            return {"id": node_id, "label": label or node_id}
        return None

    def walk(node):
        vis_nodes = []
        # Handle produce
        if "produce" in node:
            for label, producers in node["produce"].items():
                label_id = f"Label:{label}"
                label_node = add_node(label_id)
                if label_node:
                    vis_nodes.append(label_node)
                for producer in producers:
                    for rule_name, rule_data in producer.items():
                        rule_node = add_node(rule_name)
                        if rule_node:
                            vis_nodes.append(rule_node)
                        edges.append({
                            "from": rule_name,
                            "to": label_id,
                            "label": "produces"
                        })
                        # Recurse
                        sub_nodes, sub_edges = walk(rule_data)
                        vis_nodes.extend(sub_nodes)
                        edges.extend(sub_edges)

        # Handle consume
        if "consume" in node:
            for label, consumers in node["consume"].items():
                label_id = f"Label:{label}"
                label_node = add_node(label_id)
                if label_node:
                    vis_nodes.append(label_node)
                for consumer in consumers:
                    rule_name = None
                    action = None
                    for k, v in consumer.items():
                        if k == "action":
                            action = v
                        else:
                            rule_name = k
                            rule_node = add_node(rule_name)
                            if rule_node:
                                vis_nodes.append(rule_node)
                            edges.append({
                                "from": label_id,
                                "to": rule_name,
                                "label": f"consumes ({action})" if action else "consumes"
                            })
                            # Recurse
                            sub_nodes, sub_edges = walk(v)
                            vis_nodes.extend(sub_nodes)
                            edges.extend(sub_edges)

        return vis_nodes, edges

    all_nodes, all_edges = walk(data)

    # Remove duplicate edges
    seen = set()
    final_edges = []
    for e in all_edges:
        edge_tuple = (e['from'], e['to'], e['label'])
        if edge_tuple not in seen:
            seen.add(edge_tuple)
            final_edges.append(e)

    return {
        "nodes": [ {"id": n, "label": n} for n in nodes ],
        "edges": final_edges
    }

import re

def mermaid_to_vis(mermaid_text):
    node_map = {}  # label to node id
    nodes = []
    edges = []
    node_counter = 0

    def get_node_id(label):
        nonlocal node_counter
        if label not in node_map:
            node_map[label] = node_counter
            nodes.append({"id": node_counter, "label": label})
            node_counter += 1
        return node_map[label]

    # Match lines with label (e.g. A -->|label| B)
    edge_pattern = re.compile(r'^\s*([^\s]+)\s*-->\|\s*([^\|]+?)\s*\|\s*([^\s].*?)\s*$')

    for line in mermaid_text.splitlines():
        line = line.strip()
        if not line or line.startswith("graph"):
            continue

        match = edge_pattern.match(line)
        if match:
            src_label, edge_label, tgt_label = match.groups()
            src_id = get_node_id(src_label.strip())
            tgt_id = get_node_id(tgt_label.strip())
            edges.append({
                "from": src_id,
                "to": tgt_id,
                "label": edge_label.strip()
            })

    return {"nodes": nodes, "edges": edges}