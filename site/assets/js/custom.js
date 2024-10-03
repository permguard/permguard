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
    # Decode the JWT token to extract the payload
    payload = decode_jwt(token)
    # Get the list of roles from the token
    roles: List[str] = payload.get("roles", [])
    # Iterate through roles and check if any role grants the required permissions
    for role in roles:
        # Fetch permissions for this role from DB/API
        role_permissions = get_permissions_for_role(role)
        # Check if the system is defined for this role
        if system in role_permissions:
            # Check if the resource is allowed
            if resource in role_permissions[system]:
                # Check if the action is permitted
                if action in role_permissions[system][resource]:
                    # If all conditions match, permission is granted
                    return True
    # If no role grants permission, return False
    return False

has_permissions = check_permissions(token, system, "inventory", "view")`,
  after: `has_permissions = permguard.check(
    "uur::581616507495::iam:identity/google/pharmacist",
    "magicfarmacia-v0.0",
    "inventory",
    "view"
)`,
};

const GO_CODE = {
  before: `
func checkPermissions(token, system, resource, action string) bool {
    payload := decodeJWT(token)
    roles, ok := payload["roles"].([]string)
    if !ok {
        return false
    }

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
  after: `hasPermissions := permguard.Check(
    "uur::581616507495::iam:identity/google/pharmacist",
    "magicfarmacia-v0.0",
    "inventory",
    "view",
)`,
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

// Language switch
let selectedLanguage = "go";
let isPermguard = false;

const handleSelectedLanguageChange = (element) => {
  const hasSeparator = window.innerWidth >= 768;

  const languageElements = document.querySelectorAll(".code__language");
  languageElements.forEach((el) => {
    el.classList.remove("code__language--active");
  });

  element.classList.add("code__language--active");
  selectedLanguage = element.getAttribute("data-language");

  const oldLanguage = selectedLanguage === "go" ? "python" : "go";

  let codeBoxes = [];

  if (hasSeparator) {
    codeBoxes = document.querySelectorAll("img-comparison-slider pre code");

    if (selectedLanguage === "go") {
      codeBoxes[0].innerHTML = GO_CODE.before;
      codeBoxes[1].innerHTML = GO_CODE.after;
    }

    if (selectedLanguage === "python") {
      codeBoxes[0].innerHTML = PYTHON_CODE.before;
      codeBoxes[1].innerHTML = PYTHON_CODE.after;
    }
  } else {
    codeBoxes = document.querySelectorAll(".code__img--small pre code");

    if (selectedLanguage === "go") {
      codeBoxes[0].innerHTML = GO_CODE[isPermguard ? "after" : "before"];
    }

    if (selectedLanguage === "python") {
      codeBoxes[0].innerHTML = PYTHON_CODE[isPermguard ? "after" : "before"];
    }
  }

  codeBoxes.forEach((codeBox) => {
    codeBox.classList.remove(`language-${oldLanguage}`);
    codeBox.classList.add(`language-${selectedLanguage}`);
    codeBox.removeAttribute("data-highlighted");
  });

  // eslint-disable-next-line no-undef
  hljs.highlightAll();
};

const languageElements = document.querySelectorAll(".code__language");
const switchInput = document.querySelector("#switchInput");

const toggleIsPermguard = () => {
  isPermguard = !isPermguard;

  const codeBoxes = document.querySelectorAll(".code__img--small pre code");

  if (selectedLanguage === "go") {
    codeBoxes[0].innerHTML = GO_CODE[isPermguard ? "after" : "before"];
  }

  if (selectedLanguage === "python") {
    codeBoxes[0].innerHTML = PYTHON_CODE[isPermguard ? "after" : "before"];
  }

  codeBoxes.forEach((codeBox) => {
    codeBox.removeAttribute("data-highlighted");
  });

  // eslint-disable-next-line no-undef
  hljs.highlightAll();
};

languageElements.forEach((el) => {
  el.addEventListener("click", () => handleSelectedLanguageChange(el));
});

switchInput.addEventListener("change", toggleIsPermguard);
