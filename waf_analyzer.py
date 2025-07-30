AWS_MANAGED_RULE_WCU = {
    "AWSManagedRulesAdminProtectionRuleSet": 100,
    "AWSManagedRulesAmazonIpReputationList": 25,
    "AWSManagedRulesAnonymousIpList": 50,
    "AWSManagedRulesCommonRuleSet": 700,
    "AWSManagedRulesKnownBadInputsRuleSet": 200,
    "AWSManagedRulesLinuxRuleSet": 200,
    "AWSManagedRulesPHPRuleSet": 100,
    "AWSManagedRulesPOSIXRuleSet": 100,
    "AWSManagedRulesSQLiRuleSet": 200,
    "AWSManagedRulesWindowsRuleSet": 200,
    "AWSManagedRulesWordPressRuleSet": 100
}

def calculate_wcu_static(data):
    # Handle both formats
    if isinstance(data, dict) and "Rules" in data:
        rules = data["Rules"]
    elif isinstance(data, list):
        rules = data
    elif isinstance(data, dict) and "Statement" in data:
        rules = [data]
    else:
        raise ValueError("Unsupported input: expected a dict with 'Rules' or a list of rules.")

    total_wcu = 0
    details = []

    for rule in rules:
        wcu, detail = analyze_statement(rule.get("Statement", {}))
        rule_name = rule.get("Name", "Unnamed Rule")
        details.append(f"{rule_name} → {wcu} WCU ({detail})")
        total_wcu += wcu

    return {
        "WCU": total_wcu,
        "details": "\n".join(details)
    }

def calculate_match_statement_wcu(base, field_to_match, transformations):
    wcu = base

    # Add modifiers based on field
    if field_to_match:
        if "AllQueryArguments" in field_to_match:
            wcu += 10
        elif "JsonBody" in field_to_match:
            wcu *= 2

    # Add 10 WCU for each transformation *except* NONE
    if isinstance(transformations, list):
        effective = [t for t in transformations if t.get("Type") != "NONE"]
        wcu += 10 * len(effective)

    return wcu

def analyze_statement(stmt):
    if not isinstance(stmt, dict):
        return 0, "Invalid statement"

    # GeoMatchStatement
    if "GeoMatchStatement" in stmt:
        return 1, "GeoMatchStatement"

    # LabelMatchStatement
    if "LabelMatchStatement" in stmt:
        return 1, "LabelMatchStatement"

    # IPSetReferenceStatement
    if "IPSetReferenceStatement" in stmt:
        ipset = stmt["IPSetReferenceStatement"]
        base = 1
        if ipset.get("IPSetForwardedIPConfig", {}).get("Position") == "ANY":
            base += 4
        return base, "IPSetReferenceStatement"

    # ByteMatchStatement
    if "ByteMatchStatement" in stmt:
        b = stmt["ByteMatchStatement"]
        base = 1  # Base cost assumed
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "ByteMatchStatement"

    # RegexMatchStatement
    if "RegexMatchStatement" in stmt:
        b = stmt["RegexMatchStatement"]
        base = 3
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "RegexMatchStatement"

    # RegexPatternSetReferenceStatement
    if "RegexPatternSetReferenceStatement" in stmt:
        b = stmt["RegexPatternSetReferenceStatement"]
        base = 25
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "RegexPatternSetReferenceStatement"

    # SizeConstraintStatement
    if "SizeConstraintStatement" in stmt:
        b = stmt["SizeConstraintStatement"]
        base = 1
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "SizeConstraintStatement"

    # SQLiMatchStatement
    if "SqliMatchStatement" in stmt:
        b = stmt["SqliMatchStatement"]
        base = 20
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "SqliMatchStatement"

    # XssMatchStatement
    if "XssMatchStatement" in stmt:
        b = stmt["XssMatchStatement"]
        base = 40
        wcu = calculate_match_statement_wcu(base, b.get("FieldToMatch"), b.get("TextTransformations"))
        return wcu, "XssMatchStatement"

    # RateBasedStatement
    if "RateBasedStatement" in stmt:
        inner = stmt["RateBasedStatement"].get("ScopeDownStatement")
        nested_wcu, desc = analyze_statement(inner)
        return 2 + nested_wcu, f"RateBasedStatement + ({desc})"

    # ManagedRuleGroupStatement
    if "ManagedRuleGroupStatement" in stmt:
        group = stmt["ManagedRuleGroupStatement"].get("Name", "")
        vendor = stmt["ManagedRuleGroupStatement"].get("VendorName", "")
        wcu = AWS_MANAGED_RULE_WCU.get(group, 100)  # fallback default
        return wcu, f"ManagedRuleGroupStatement ({vendor}/{group}) → {wcu} WCU"

    # Logical: And / Or
    for key in ["AndStatement", "OrStatement"]:
        if key in stmt:
            logical_block = stmt[key]
            statements = logical_block.get("Statements", [])
            total = 1
            sub_descs = []
            for s in statements:
                wcu, desc = analyze_statement(s)
                total += wcu
                sub_descs.append(desc)
            return total, f"{key} with {len(statements)} subrules: " + ", ".join(sub_descs)

    # NotStatement
    if "NotStatement" in stmt:
        inner = stmt["NotStatement"].get("Statement")
        nested_wcu, desc = analyze_statement(inner)
        return 1 + nested_wcu, f"NotStatement: {desc}"

    return 0, "Unsupported or unknown statement"
