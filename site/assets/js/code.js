export const LANGUAGES_CODE = {
  go: {
    before: `// BEFORE

func getPermissionsForRole(role string) map[string]map[string][]string {
  // Here boilerplate code to fetch permissions for a role
  return permissions
}

func checkPermissions(token, system, resource, action string) bool {
  payload := decodeJWT(token)
  roles, ok := payload["role"].([]string)
  if !ok {
      return false
  }

  for _, role := range roles {
      rolePermissions := getPermissionsForRole(role)
      if resources, systemFound := rolePermissions[resource]; systemFound {
          if actions, resourceFound := resources[system]; resourceFound {
              for _, allowedAction := range actions {
                  if strings.EqualFold(allowedAction, action) {
                      return true
                  }
              }
          }
      }
  }
  return false
}

hasPermissions := checkPermissions(token, system, "subscription", "view")
if hasPermissions {
  fmt.Println("✅ Authorization Permitted")
} else {
fmt.Println("❌ Authorization Denied")
}`,
    after: `// AFTER

azClient := permguard.NewAZClient(
    permguard.WithEndpoint("localhost", 9094),
)

req := azreq.NewAZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
    "amy.smith@acmecorp.com", "MagicFarmacia::Platform::Subscription", "MagicFarmacia::Platform::Action::create").
    Build()

ok, _, _ := azClient.Check(req)
if decsion {
    fmt.Println("✅ Authorization Permitted")
} else {
    fmt.Println("❌ Authorization Denied")
}`,
  },

  python: {
    before: `# BEFORE

def get_permissions_for_role(role: str) -> dict[str, dict[str, list[str]]]:
    return {}

def check_permissions(token: str, system: str, resource: str, action: str) -> bool:
    payload = jwt.decode(token, options={"verify_signature": False})
    roles = payload.get("role", [])

    if not isinstance(roles, list):
        return False

    for role in roles:
        role_permissions = get_permissions_for_role(role)
        if resource in role_permissions and system in role_permissions[resource]:
            if action.lower() in map(str.lower, role_permissions[resource][system]):
                return True
    return False

has_permissions = check_permissions(token, system, "subscription", "view")

print("✅ Authorization Permitted" if has_permissions else "❌ Authorization Denied")`,
    after: `# AFTER

from permguard import AZClient, AZAtomicRequestBuilder, WithEndpoint

az_client = AZClient(WithEndpoint("localhost", 9094))

req = (AZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
        "amy.smith@acmecorp.com", "MagicFarmacia::Platform::Subscription",
        "MagicFarmacia::Platform::Action::create")
       .build())

ok, _, _ = az_client.check(req)

print("✅ Authorization Permitted" if ok else "❌ Authorization Denied")
`,
  },
  typescript: {
    before: `// BEFORE

function getPermissionsForRole(role) {
  // Here boilerplate code to fetch permissions for a role
  return {
    "subscription": {
      "platform": ["view", "create"]
    }
  };
}

function checkPermissions(token, system, resource, action) {
  const payload = decodeJWT(token);
  const roles = payload.role || [];

  if (!Array.isArray(roles)) {
    return false;
  }

  for (const role of roles) {
    const rolePermissions = getPermissionsForRole(role);
    if (rolePermissions[resource] && rolePermissions[resource][system]) {
      if (rolePermissions[resource][system].includes(action.toLowerCase())) {
        return true;
      }
    }
  }
  return false;
}

const hasPermissions = checkPermissions(token, "platform", "subscription", "create");

if (hasPermissions) {
  console.log("✅ Authorization Permitted");
} else {
  console.log("❌ Authorization Denied");
}`,
    after: `// AFTER

import { 
  PrincipalBuilder,
  AZAtomicRequestBuilder,
  withEndpoint,
  AZClient,
} from "permguard-node";

const azClient = new AZClient(withEndpoint("localhost", 9094));

const principal = new PrincipalBuilder("amy.smith@acmecorp.com").build();

const req = new AZAtomicRequestBuilder(
  583438038653,
  "46706cb00ea248d6841cfe2c9f02205b",
  "platform-creator",
  "MagicFarmacia::Platform::Subscription",
  "MagicFarmacia::Platform::Action::create"
)
  .withRequestID("1234")
  .withPrincipal(principal)
  .withSubjectSource("keycloack")
  .build();

const { decision } = await azClient.check(req);

console.log(decision ? "✅ Authorization Permitted" : "❌ Authorization Denied");`,
  },
};
