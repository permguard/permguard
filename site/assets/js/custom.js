/**
 * Copyright 2024 Nitro Agility S.r.l.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

// Put your custom JS code here

const PYTHON_CODE = {
  before: `# Function to check if the user has permission to perform an action
def check_permissions(token: str, system: str, resource: str, action: str):
    payload = decode_jwt(token)  # Decode the JWT token to extract the payload
    roles: List[str] = payload.get("roles", [])  # Get the list of roles from the token
    
    # Iterate through roles and check if any role grants the required permissions
    for role in roles:
        role_permissions = get_permissions_for_role(role)  # Fetch permissions for this role from DB/API
        if system in role_permissions:  # Check if the system is defined for this role
            if resource in role_permissions[system]:  # Check if the resource is allowed
                if action in role_permissions[system][resource]:  # Check if the action is permitted
                    return True  # If all conditions match, permission is granted
    return False  # If no role grants permission, return False
    
has_permissions = check_permissions(token, system, "inventory", "view")`,
  after: `has_permissions = permguard.check("uur::581616507495::iam:identity/google/pharmacist", "magicfarmacia-v0.0", "inventory", "view")`,
};

const GO_CODE = {
  before: `// Function to check if the user has permission to perform an action
func checkPermissions(token, system, resource, action string) bool {
	payload := decodeJWT(token)
	roles, ok := payload["roles"].([]string)
	if !ok {
		return false
	}

	// Iterate through roles and check if any role grants the required permissions
	for _, role := range roles {
		rolePermissions := getPermissionsForRole(role)
		if resources, systemFound := rolePermissions[resource]; systemFound {
			if actions, resourceFound := resources[system]; resourceFound {
				for _, allowedAction := range actions {
					if strings.EqualFold(allowedAction, action) {
						return true // Permission granted
					}
				}
			}
		}
	}
	return false // No permission granted
}

hasPermissions := checkPermissions(token, system, "inventory", "view")`,
  after: `hasPermissions := permguard.Check("uur::581616507495::iam:identity/google/pharmacist", "magicfarmacia-v0.0", "inventory", "view")`,
};

const handleScroll = () => {
  const header = document.querySelector("header");

  if (window.scrollY === 0) {
    header.classList.remove("header--blur");
  } else {
    header.classList.add("header--blur");
  }
};

handleScroll();

window.addEventListener("scroll", handleScroll);

const handleSelectedLanguageChange = (element) => {
  const languageElements = document.querySelectorAll(".code__language");

  languageElements.forEach((el) => {
    el.classList.remove("code__language--active");
  });

  element.classList.add("code__language--active");

  const language = element.getAttribute("data-language");
  const oldLanguage = language === "go" ? "python" : "go";

  const codeBoxes = document.querySelectorAll("img-comparison-slider pre code");

  if (language === "go") {
    codeBoxes[0].innerHTML = GO_CODE.before;
    codeBoxes[1].innerHTML = GO_CODE.after;
  }

  if (language === "python") {
    codeBoxes[0].innerHTML = PYTHON_CODE.before;
    codeBoxes[1].innerHTML = PYTHON_CODE.after;
  }

  codeBoxes[0].classList.remove(`language-${oldLanguage}`);
  codeBoxes[1].classList.remove(`language-${oldLanguage}`);

  codeBoxes[0].classList.add(`language-${language}`);
  codeBoxes[1].classList.add(`language-${language}`);

  codeBoxes[0].removeAttribute("data-highlighted");
  codeBoxes[1].removeAttribute("data-highlighted");

  // eslint-disable-next-line no-undef
  hljs.highlightAll();
};

const languageElements = document.querySelectorAll(".code__language");

languageElements.forEach((el) => {
  el.addEventListener("click", () => handleSelectedLanguageChange(el));
});
