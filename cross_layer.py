from policyanalyzer import Policy

import ipaddress

class ApplicationPolicy:
    def __init__(self, subject, resource, action):
        self.subject = subject
        self.resource = resource
        self.action = action.upper()
    def __repr__(self):
        return f"{self.subject} -> {self.resource} ({self.action})"

def resources_overlap(net_resource, app_resource):


    try:
        net1 = ipaddress.ip_network(net_resource, strict=False)
        net2 = ipaddress.ip_network(app_resource, strict=False)

        return net1.overlaps(net2)

    except ValueError:
        return False

def normalize_action(action):


    action = action.upper().strip()

    if action == "ACCEPT":
        return "ALLOW"

    return action



def detect_cross_layer_conflicts(network_policies, app_policies):
    conflicts = []

    for net in network_policies:
        for app in app_policies:

            net_resource = str(net.fields["dst"])
            net_action = normalize_action(str(net.action))            
            
            if resources_overlap(net_resource, app.resource):                

                if net_action != normalize_action(app.action):


                    conflict_type = "ACTION_MISMATCH"

                    if net_action == "ALLOW" and normalize_action(app.action) == "DENY":
                        severity = "HIGH"

                    elif net_action == "DENY" and normalize_action(app.action) == "ALLOW":
                        severity = "CRITICAL"

                    else:
                        severity = "MEDIUM"

                    conflicts.append({
                        "network_rule": str(net),
                        "application_rule": str(app),
                        "type": conflict_type,
                        "severity": severity,
                        "description": f"Network {net_action} vs Application {app.action}"
                    })
                    

                    
    return conflicts

if __name__ == "__main__":

    network_policies = [
     Policy(
        protocol="TCP",
        src="ANY",
        s_port="ANY",
        dst="10.0.0.1/32",
        d_port="80",
        action="ALLOW"
        ),
     Policy(
        protocol="TCP",
        src="ANY",
        s_port="ANY",
        dst="10.0.0.2/32",
        d_port="443",
        action="DENY"
        ),
     Policy(
        protocol="TCP",
        src="ANY",
        s_port="ANY",
        dst="10.0.0.3/32",
        d_port="22",
        action="ALLOW"
    ),
     Policy(
        protocol="TCP",
        src="ANY",
        s_port="ANY",
        dst="10.0.0.0/24",
        d_port="8080",
        action="ALLOW"
        )

     ]

    app_policies = [
     ApplicationPolicy(
        "user1",
        "10.0.0.1/32",
        "DENY"
        ),
     ApplicationPolicy(
        "admin",
        "10.0.0.2/32",
        "ALLOW"
        ),
     ApplicationPolicy(
        "guest",
        "10.0.0.3/32",
        "ALLOW"
     ),
     ApplicationPolicy(
        "developer",
        "10.0.0.5/32",
        "DENY"
        )


    ]

    conflicts = detect_cross_layer_conflicts(
     network_policies,
     app_policies
    )
    print("\nCross-layer conflicts:\n")

    for c in conflicts:
        print(f"[{c['severity']}] Cross-layer conflict detected")
        print("Type          :", c["type"])
        print("Network Rule  :", c["network_rule"])
        print("Application   :", c["application_rule"])
        print("Description   :", c["description"])
        print()

    print("Total conflicts:", len(conflicts))

    critical = sum(1 for c in conflicts if c["severity"] == "CRITICAL")
    high = sum(1 for c in conflicts if c["severity"] == "HIGH")

    print("Critical conflicts:", critical)
    print("High conflicts:", high)
    
    print("\n===== SUMMARY =====")
    print("Total network policies:", len(network_policies))
    print("Total application policies:", len(app_policies))
    print("Total detected conflicts:", len(conflicts))


    import json

    with open("conflicts.json", "w") as f:
        json.dump(conflicts, f, indent=4)
