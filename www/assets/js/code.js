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

import (
 "github.com/permguard/sdk-go"
 "github.com/permguard/sdk-go/az/azreq"
)

azClient := permguard.NewAZClient(
    permguard.WithEndpoint("localhost", 9094),
)

req := azreq.NewAZAtomicRequestBuilder(273165098782, "fd1ac44e4afa4fc4beec622494d3175a",
    "amy.smith@acmecorp.com", "ZTMedFlow::Platform::Subscription", "ZTMedFlow::Platform::Action::create").
    WithResourceID("e3a786fd07e24bfa95ba4341d3695ae8").
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
    # Here boilerplate code to fetch permissions for a role
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
from permguard.az.azreq.model import AZRequest
from permguard.az_client import AZClient
from permguard.az_config import with_endpoint

az_client = AZClient(with_endpoint("localhost", 9094))

req = (
    AZAtomicRequestBuilder(895741663247,"809257ed202e40cab7e958218eecad20",
        "platform-creator", "ZTMedFlow::Platform::Subscription",
        "ZTMedFlow::Platform::Action::create",
    )
    .with_resource_id("e3a786fd07e24bfa95ba4341d3695ae8")
    .build()
)

decision, _ = az_client.check(req)

print("✅ Authorization Permitted" if ok else "❌ Authorization Denied")`,
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
  AZClient,
  withEndpoint,
  AZAtomicRequestBuilder
} from "sdk-node";

const azClient = new AZClient(withEndpoint("localhost", 9094));

const req = new AZAtomicRequestBuilder(
  583438038653, "46706cb00ea248d6841cfe2c9f02205b",
  "platform-creator", "ZTMedFlow::Platform::Subscription",
  "ZTMedFlow::Platform::Action::create"
).withResourceID("e3a786fd07e24bfa95ba4341d3695ae8").build();

const { decision } = await azClient.check(req);

console.log(decision ? "✅ Authorization Permitted" : "❌ Authorization Denied");`,
  },
  csharp: {
    before: `// BEFORE
public static Dictionary<string, Dictionary<string, List<string>>> GetPermissionsForRole(string role)
{
    // Here boilerplate code to fetch permissions for a role
    return new Dictionary<string, Dictionary<string, List<string>>>();
}

public static bool CheckPermissions(string token, string system, string resource, string action)
{
    // Here boilerplate code to check permissions
    // ...
    foreach (var role in roles)
    {
        var rolePermissions = GetPermissionsForRole(role);
        if (rolePermissions.TryGetValue(resource, out var resources) &&
            resources.TryGetValue(system, out var actions) &&
            actions.Any(a => string.Equals(a, action, StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }
    }
    return false;
}

public static Dictionary<string, object> DecodeJWT(string token)
{
    // Placeholder: Implement JWT decoding logic here
    return new Dictionary<string, object>();
}

public static void Main()
{
    string token = "exampleToken";
    string system = "exampleSystem";

    bool hasPermissions = CheckPermissions(token, system, "subscription", "view");
    if (hasPermissions)
    {
        Console.WriteLine("✅ Authorization Permitted");
    }
    else
    {
        Console.WriteLine("❌ Authorization Denied");
    }
}`,
    after: `// AFTER
using Permguard;
using Permguard.AzReq;

var config = new AzConfig().WithEndpoint(new AzEndpoint("http", 9094, "localhost"));
var client = new AzClient(config);

var request = new AzAtomicRequestBuilder(285374414806, "f81aec177f8a44a48b7ceee45e05507f",
        "platform-creator", "ZTMedFlow::Platform::Subscription",
        "ZTMedFlow::Platform::Action::create")
    .WithResourceId("e3a786fd07e24bfa95ba4341d3695ae8").Build();

var response = client.CheckAuth(request);
if (response == null)
{
    Console.WriteLine("❌ Failed to check auth.");
    return;
}
Console.WriteLine(response.Decision ? "✅ Authorization Permitted" : "❌ Authorization Denied");`,},
  java: {
    before: `// BEFORE

public static Map<String, Map<String, List<String>>> getPermissionsForRole(String role) {
    // Here boilerplate code to fetch permissions for a role
    return new HashMap<>(); // Replace with actual permission retrieval logic
}

public static boolean checkPermissions(String token, String system, String resource, String action) {
    // Here boilerplate code to check permissions
    // ...
    for (String role : roles) {
        Map<String, Map<String, List<String>>> rolePermissions = getPermissionsForRole(role);
        if (rolePermissions.containsKey(resource)) {
            Map<String, List<String>> resources = rolePermissions.get(resource);
            if (resources.containsKey(system)) {
                List<String> actions = resources.get(system);
                for (String allowedAction : actions) {
                    if (allowedAction.equalsIgnoreCase(action)) {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

public static Map<String, Object> decodeJWT(String token) {
    // Placeholder: Implement JWT decoding logic
    return new HashMap<>();
}

public static void main(String[] args) {
    String token = "exampleToken";
    String system = "exampleSystem";

    boolean hasPermissions = checkPermissions(token, system, "subscription", "view");
    if (hasPermissions) {
        System.out.println("✅ Authorization Permitted");
    } else {
        System.out.println("❌ Authorization Denied");
    }
}`,
    after: `// AFTER
import com.permguard.pep.builder.*;
import com.permguard.pep.client.AZClient;
import com.permguard.pep.config.AZConfig;
import com.permguard.pep.model.request.*;
import com.permguard.pep.model.response.AZResponse;

AZConfig config = new AZConfig("localhost", 9094, true);
AZClient client = new AZClient(config);

AZRequest request = new AZAtomicRequestBuilder(611159836099L, "f81aec177f8a44a48b7ceee45e05507f",,
        "amy.smith@acmecorp.com", "ZTMedFlow::Platform::Subscription",
        "ZTMedFlow::Platform::Action::create"
).withResourceId("e3a786fd07e24bfa95ba4341d3695ae8").build();

AZResponse response = client.check(request);
if (response == null) {
    System.out.println("❌ Authorization request failed.");
    return;
}

if (response.isDecision()) {
    System.out.println("✅ Authorization Permitted");
} else {
    System.out.println("❌ Authorization request failed.");
}`,
  },
};
