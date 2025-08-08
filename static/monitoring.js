// @license magnet:?xt=urn:btih:d3d9a9a6595521f9666a5e94cc830dab83b65699&dn=expat.txt MIT

const fingerprintSplitInterval = 4;
const createForm = document.getElementById("create_form");
const createFormContent = document.getElementById("create_form_content");
const createUsername = document.getElementById("create_username");
const createPassword = document.getElementById("create_password");
const createPasswordConfirm = document.getElementById("create_password_confirm");
const loginForm = document.getElementById("login_form");
const loginUsername = document.getElementById("login_username");
const loginPassword = document.getElementById("login_password");
const loginStatus = document.getElementById("login_status");
const username = document.getElementById("username");
const loggedOutButtons = document.getElementById("logged_out_buttons");
const loggedInButtons = document.getElementById("logged_in_buttons");
const logout = document.getElementById("logout");
const logoutEverywhere = document.getElementById("logout_everywhere");
const changePasswordForm = document.getElementById("change_password_form");
const configuration = document.getElementById("configuration");
const devices = document.getElementById("devices");
const qr = document.getElementById("qr");
const rotate = document.getElementById("rotate");
const accountContent = document.getElementById("account_content");

const deviceAdminStrings = new Map([
    [0, "no"],
    [1, "yes, but only system apps"],
    [2, "yes, with non-system apps"]
]);

function post(resource, body) {
    return fetch(resource, {
        method: "POST",
        mode: "same-origin",
        headers: {"Content-Type": "application/json"},
        body: body
    });
}

function formatOsVersion(osVersion) {
    const padded = ("000000" + osVersion).slice(-6);
    return parseInt(padded.substring(0, 2)) + "." +
        parseInt(padded.substring(2, 4)) + "." +
        parseInt(padded.substring(4, 6));
}

function formatPatchLevel(patchLevel) {
    const s = patchLevel.toString();
    return s.substring(0, 4) + "-" + s.substring(4, 6) +
        (s.length >= 8 ? "-" + s.substring(6, 8) : "");
}

function toYesNoString(value) {
    if (value === undefined) {
        return "unknown";
    }
    return value ? "yes" : "no";
}

function toAppVariantString(appVariant) {
    if (appVariant == 0) {
        return "Release build signed by GrapheneOS";
    } else if (appVariant == 1) {
        return "Release build signed by Play Store";
    } else if (appVariant == 2) {
        return "Debug build signed by GrapheneOS";
    }
    throw new Error("Invalid app variant");
}

function toSecurityLevelString(securityLevel, attestKey) {
    if (securityLevel == 2) {
        if (attestKey) {
            return "High — StrongBox Hardware Security Module (HSM) with pairing specific attest key";
        } else {
            return "Standard — StrongBox Hardware Security Module (HSM)";
        }
    } else if (securityLevel == 1) {
        if (attestKey) {
            return "Standard — Trusted Execution Environment (TEE) with pairing specific attest key";
        } else {
            return "Standard — Trusted Execution Environment (TEE)";
        }
    }
    throw new Error("Invalid security level");
}

function autoRebootTimeoutString(autoRebootSeconds) {
    if (autoRebootSeconds >= 0) {
        const duration = {
            hours: Math.floor(autoRebootSeconds / 60 / 60),
            minutes: Math.floor(autoRebootSeconds / 60) % 60,
            seconds: autoRebootSeconds % 60,
        };
        if (typeof window.Intl.DurationFormat == "function") {
            const durationFormat = new Intl.DurationFormat("en", {style: "long"});
            return durationFormat.format(duration);
        } else {
            let durationString = "";
            if (duration.hours > 0) {
                durationString += duration.hours + " hour" + ((duration.hours > 1 ? "s" : ""));
            }

            if (duration.minutes > 0) {
                if (durationString.length > 0) {
                    durationString += ", ";
                }
                durationString += duration.minutes + " minute" + ((duration.minutes > 1 ? "s" : ""));
            }

            if (duration.seconds > 0) {
                if (durationString.length > 0) {
                    durationString += ", ";
                }
                durationString += duration.seconds + " second" + ((duration.seconds > 1 ? "s" : ""));
            }

            return durationString;
        }
    } else if (autoRebootSeconds == -2) {
        return "Invalid";
    }
    throw new Error("Invalid auto reboot minutes value");
}

function usbPortSecurityModeString(portSecurityMode, hasPogoPins) {
    if (portSecurityMode >= 0) {
        switch (portSecurityMode) {
            case 0: return (hasPogoPins > 0) ? "USB-C port off, pogo pins used only for charging" : "Off";
            case 1: return "Charging-only";
            case 2: return "Charging-only when locked";
            case 3: return "Charging-only when locked, except before first unlock";
            case 4: return "On";
            default: break;
        }
    } else if (portSecurityMode == -2) {
        return "Invalid";
    }
    throw new Error("Invalid port security mode value");
}

function userCountString(userCount) {
    if (userCount > 0) {
        return userCount;
    } else if (userCount == -2) {
        return "Invalid";
    }
    throw new Error("Invalid port security mode value");
}

function oemUnlockAllowedString(oemUnlockAllowed2) {
    if (oemUnlockAllowed2 >= 0) {
        return toYesNoString(oemUnlockAllowed2 > 0);
    } else if (oemUnlockAllowed2 == -2) {
        return "Invalid";
    }
    throw new Error("Invalid oem unlock allowed value");
}

function reloadQrCode() {
    qr.src = "/placeholder.gif";
    qr.alt = "";
    post("/api/account.png").then(response => {
        if (!response.ok) {
            return Promise.reject(new Error(response.status));
        }
        return response.blob();
    }).then(imageBlob => {
        qr.src = URL.createObjectURL(imageBlob);
        qr.alt = "account QR code";
    }).catch(error => {
        console.log(error);
    });
}

function displayLogin(account) {
    loggedOutButtons.hidden = true;
    loggedInButtons.hidden = false;
    loginStatus.hidden = false;
    username.innerText = account.username;
    configuration.verify_interval.value = account.verifyInterval / 60 / 60;
    configuration.alert_delay.value = account.alertDelay / 60 / 60;
    accountContent.hidden = false;
    if (account.email !== undefined) {
        configuration.email.value = account.email;
    }
    reloadQrCode();
    fetchDevices();
}

function create(tagName, text, className, hidden = false) {
    const element = document.createElement(tagName);
    element.innerText = text;
    element.hidden = hidden;
    if (className !== undefined) {
        element.className = className;
    }
    return element;
}

function appendLine(element, text) {
    element.appendChild(document.createTextNode(text));
    element.appendChild(document.createElement("br"));
}

function fetchHistory(parent, nextOffset, hasPogoPins) {
    const parentdata = parent.dataset;
    parentdata.offsetId = Number(nextOffset);
    post("/api/attestation-history.json", JSON.stringify({
        fingerprint: parentdata.deviceFingerprint,
        offsetId: Number(parentdata.offsetId)
    })).then(response => {
        if (!response.ok) {
            return Promise.reject(new Error(response.status));
        }
        return response.json();
    }).then(attestations => {
        for (const attestation of attestations) {
            parent.appendChild(create("h4", new Date(attestation.time)));

            const p = parent.appendChild(document.createElement("p"));
            const result = attestation.strong ?
                "Successfully performed strong paired verification and identity confirmation." :
                "Successfully performed basic initial verification and pairing.";
            p.appendChild(create("strong", result));

            parent.appendChild(create("h5", "Hardware verified information (constants omitted):"));
            appendLine(parent, "OS version: " + formatOsVersion(attestation.osVersion));
            appendLine(parent, "OS patch level: " + formatPatchLevel(attestation.osPatchLevel));
            if (attestation.vendorPatchLevel !== undefined) {
                appendLine(parent, "Vendor patch level: " + formatPatchLevel(attestation.vendorPatchLevel));
            }
            if (attestation.bootPatchLevel !== undefined) {
                appendLine(parent, "Boot patch level: " + formatPatchLevel(attestation.bootPatchLevel));
            }
            if (attestation.verifiedBootHash !== undefined) {
                parent.appendChild(document.createTextNode("Verified boot hash: "));
                parent.appendChild(create("span", attestation.verifiedBootHash, "fingerprint"));
                parent.appendChild(document.createElement("br"));
            }

            parent.appendChild(create("h5", "Information provided by the verified OS:"));
            appendLine(parent, "Pinned Auditor app version: " + attestation.appVersion);
            appendLine(parent, "User profile secure: " + toYesNoString(attestation.userProfileSecure));
            appendLine(parent, "Enrolled biometrics: " + toYesNoString(attestation.enrolledBiometrics));
            appendLine(parent, "Accessibility service(s) enabled: " + toYesNoString(attestation.accessibility));
            appendLine(parent, "Device administrator(s) enabled: " + deviceAdminStrings.get(attestation.deviceAdmin));
            appendLine(parent, "Android Debug Bridge enabled: " + toYesNoString(attestation.adbEnabled));
            appendLine(parent, "Add users from lock screen: " + toYesNoString(attestation.addUsersWhenLocked));
            if (attestation.oemUnlockAllowed2 !== undefined && attestation.oemUnlockedAllowed2 >= 0) {
                appendLine(parent, "OEM unlocking allowed: " + oemUnlockAllowedString(attestation.oemUnlockAllowed2));
            }
            appendLine(parent, "Main user account: " + toYesNoString(attestation.systemUser));
            if (attestation.autoRebootSeconds !== undefined && attestation.autoRebootSeconds >= 20) {
                appendLine(parent, "Auto reboot timeout: " + autoRebootTimeoutString(attestation.autoRebootSeconds));
            }
            if (attestation.portSecurityMode !== undefined && attestation.portSecurityMode >= 0) {
                appendLine(parent, "USB-C port" + ((attestation.hasPogoPins > 0) ? " and pogo pins" : "")
                        + " security mode: " + usbPortSecurityModeString(attestation.portSecurityMode, hasPogoPins));
            }
            if (attestation.userCount !== undefined && attestation.userCount >= 1) {
                appendLine(parent, "User count: " + userCountString(attestation.userCount));
            }
        }
        const earliestCurrentId = attestations.slice(-1)[0].id;
        function fetchHistoryNextPage() {
            parent.removeChild(parent.lastChild);
            return fetchHistory(parent, earliestCurrentId - 1, hasPogoPins);
        }
        if (earliestCurrentId !== Number(parentdata.minId)) {
            parent.appendChild(create("button", "Load More", "page_history_next")).onclick = fetchHistoryNextPage;
        }
    });
}

function fetchDevices() {
    devices.appendChild(create("p", "Loading device data..."));

    post("/api/devices.json").then(response => {
        if (!response.ok) {
            return Promise.reject(new Error(response.status));
        }
        return response.json();
    }).then(devicesJson => {
        devices.innerText = null;
        for (const device of devicesJson) {
            let fingerprint = "";
            for (let i = 0; i < device.fingerprint.length; i += fingerprintSplitInterval) {
                fingerprint += device.fingerprint.substring(i, Math.min(device.fingerprint.length, i + fingerprintSplitInterval));
                if (i + fingerprintSplitInterval < device.fingerprint.length) {
                    fingerprint += "-";
                }
            }

            const info = devices.appendChild(document.createElement("article"));
            const header = create("h2", null, "fingerprint");
            header.id = fingerprint;
            const link = create("a", fingerprint);
            link.href = "#" + fingerprint;
            header.appendChild(link);
            info.appendChild(header);

            const deleteButton = info.appendChild(create("button", "delete device"));
            deleteButton.onclick = event => {
                if (confirm(`Are you sure you want to delete the device ${fingerprint}?`)) {
                    event.target.disabled = true;

                    const data = JSON.stringify({
                        "fingerprint": device.fingerprint
                    });
                    post("/api/delete-device", data).then(response => {
                        if (!response.ok) {
                            return Promise.reject(new Error(response.status));
                        }
                        event.target.disabled = false;
                        devices.removeChild(info);
                    }).catch(error => {
                        event.target.disabled = false;
                        console.log(error);
                    });
                }
            };

            info.appendChild(create("h3", "Hardware verified information:"));
            info.appendChild(document.createTextNode("Pairing identity (hash of pinned hardware-backed key): "));
            info.appendChild(create("span", fingerprint, "fingerprint"));
            info.appendChild(document.createElement("br"));
            appendLine(info, "Pinned security level: " + toSecurityLevelString(device.pinnedSecurityLevel, device.attestKey));
            appendLine(info, "Pinned device: " + device.name);
            appendLine(info, `Pinned OS: ${device.osName} (unmodified official release)`);
            appendLine(info, "Pinned OS version: " + formatOsVersion(device.pinnedOsVersion));
            appendLine(info, "Pinned OS patch level: " + formatPatchLevel(device.pinnedOsPatchLevel));
            if (device.pinnedVendorPatchLevel !== undefined) {
                appendLine(info, "Pinned vendor patch level: " + formatPatchLevel(device.pinnedVendorPatchLevel));
            }
            if (device.pinnedBootPatchLevel !== undefined) {
                appendLine(info, "Pinned boot patch level: " + formatPatchLevel(device.pinnedBootPatchLevel));
            }
            info.appendChild(document.createTextNode("Pinned verified boot key hash: "));
            info.appendChild(create("span", device.verifiedBootKey, "fingerprint"));
            info.appendChild(document.createElement("br"));
            if (device.verifiedBootHash !== undefined) {
                info.appendChild(document.createTextNode("Verified boot hash: "));
                info.appendChild(create("span", device.verifiedBootHash, "fingerprint"));
                info.appendChild(document.createElement("br"));
            }

            info.appendChild(create("button", "show advanced information", "toggle"));
            const advanced = info.appendChild(document.createElement("section"));
            advanced.hidden = true;
            const length = device.pinnedCertificates.length;
            for (const [i, certificate] of device.pinnedCertificates.entries()) {
                let label = "";
                if (i == 0) {
                    label = " (persistent Auditor key)";
                } else if (device.attestKey && i == 1) {
                    label = " (persistent Auditor attest key)";
                } else if (i == 1 + device.attestKey) {
                    label = length > 4 + device.attestKey ? " (remotely provisioned)" : " (batch)";
                } else if (i < length - 1) {
                    label = " (intermediate)";
                } else if (i == length - 1) {
                    label = " (root)";
                }
                if (i > 0) {
                    advanced.appendChild(document.createElement("br"));
                }
                advanced.appendChild(document.createTextNode(`Pinned certificate ${i}${label}: `));
                advanced.appendChild(create("button", "show", "toggle"));
                advanced.appendChild(create("pre", certificate, undefined, true));
            }

            info.appendChild(create("h3", "Information provided by the verified OS:"));
            appendLine(info, "Pinned Auditor app version: " + device.pinnedAppVersion);
            appendLine(info, "Pinned Auditor app variant: " + toAppVariantString(device.pinnedAppVariant));
            appendLine(info, "User profile secure: " + toYesNoString(device.userProfileSecure));
            if (device.pinnedAppVersion < 26) {
                appendLine(info, "Enrolled fingerprints: " + toYesNoString(device.enrolledBiometrics));
            } else {
                appendLine(info, "Enrolled biometrics: " + toYesNoString(device.enrolledBiometrics));
            }
            appendLine(info, "Accessibility service(s) enabled: " + toYesNoString(device.accessibility));
            appendLine(info, "Device administrator(s) enabled: " + deviceAdminStrings.get(device.deviceAdmin));
            appendLine(info, "Android Debug Bridge enabled: " + toYesNoString(device.adbEnabled));
            appendLine(info, "Add users from lock screen: " + toYesNoString(device.addUsersWhenLocked));
            if (device.oemUnlockAllowed2 !== undefined && device.oemUnlockAllowed2 >= 0) {
                appendLine(info, "OEM unlocking allowed: " + oemUnlockAllowedString(device.oemUnlockAllowed2));
            }
            appendLine(info, "Main user account: " + toYesNoString(device.systemUser));
            if (device.autoRebootSeconds !== undefined && device.autoRebootSeconds >= 20) {
                appendLine(info, "Auto reboot timeout: " + autoRebootTimeoutString(device.autoRebootSeconds));
            }
            if (device.portSecurityMode !== undefined && device.portSecurityMode >= 0) {
                appendLine(info, "USB-C port" + ((device.hasPogoPins > 0) ? " and pogo pins" : "") + " security mode: " + usbPortSecurityModeString(device.portSecurityMode, device.hasPogoPins));
            }
            if (device.userCount !== undefined && device.userCount >= 1) {
                appendLine(info, "User count: " + userCountString(device.userCount));
            }

            info.appendChild(create("h3", "Attestation history"));
            appendLine(info, "First verified time: " + new Date(device.verifiedTimeFirst));
            appendLine(info, "Last verified time: " + new Date(device.verifiedTimeLast));
            const historyButton = info.appendChild(create("button", "show detailed history", "toggle"));
            const history = info.appendChild(document.createElement("div"));
            history.dataset.deviceFingerprint = device.fingerprint;
            history.dataset.minId = Number(device.minId);
            history.dataset.maxId = Number(device.maxId);
            history.hidden = true;
            // always starts with latest attestation history entry
            historyButton.onclick = fetchHistory(history, device.maxId, device.hasPogoPins);
        }

        for (const toggle of document.getElementsByClassName("toggle")) {
            toggle.onclick = event => {
                const target = event.target;
                const cert = target.nextSibling;
                if (!cert.hidden) {
                    target.innerText = target.innerText.replace("hide", "show");
                    cert.hidden = true;
                } else {
                    target.innerText = target.innerText.replace("show", "hide");
                    cert.hidden = false;
                }
            };
        }

        const old = location.hash;
        location.hash = "";
        location.hash = old;
    }).catch(error => {
        console.log(error);
        devices.innerText = null;
        devices.appendChild(create("p", "Failed to fetch device data."));
    });
}

post("/api/account").then(response => {
    if (!response.ok) {
        return Promise.reject(new Error(response.status));
    }
    return response.json();
}).then(account => {
    displayLogin(account);
}).catch(error => {
    console.log(error);
    loggedOutButtons.hidden = false;
});

document.getElementById("create").onclick = () => {
    loggedOutButtons.hidden = true;
    createFormContent.hidden = false;
};

createPasswordConfirm.oninput = () => {
    if (createPassword.value === createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("");
    }
};

changePasswordForm.new_password.oninput = () => {
    if (changePasswordForm.new_password.value !== changePasswordForm.current_password.value) {
        changePasswordForm.new_password.setCustomValidity("");
    }
};

changePasswordForm.new_password_confirm.oninput = () => {
    if (changePasswordForm.new_password.value === changePasswordForm.new_password_confirm.value) {
        changePasswordForm.new_password_confirm.setCustomValidity("");
    }
};

function clearAlertDelayValidity() {
    if (parseInt(configuration.alert_delay.value) > parseInt(configuration.verify_interval.value)) {
        configuration.alert_delay.setCustomValidity("");
    }
}

configuration.verify_interval.oninput = clearAlertDelayValidity;
configuration.alert_delay.oninput = clearAlertDelayValidity;

function clearValidity(event) {
    event.currentTarget.setCustomValidity("");
}

createUsername.oninput = clearValidity;
loginUsername.oninput = clearValidity;
loginPassword.oninput = clearValidity;

function login(username, password) {
    const loginJson = JSON.stringify({username: username, password: password});
    post("/api/login", loginJson).then(response => {
        if (!response.ok) {
            if (response.status === 400) {
                loginUsername.setCustomValidity("Username does not exist");
                loginUsername.reportValidity();
            } else if (response.status === 403) {
                loginPassword.setCustomValidity("Incorrect password");
                loginPassword.reportValidity();
            }
            return Promise.reject(new Error(response.status));
        }
        post("/api/account").then(response => {
            if (!response.ok) {
                return Promise.reject(new Error(response.status));
            }
            return response.json();
        }).then(account => {
            loginForm.hidden = true;
            loginForm.reset();
            loginForm.submit.disabled = false;
            displayLogin(account);
        }).catch(error => {
            console.log(error);
        });
    }).catch(error => {
        loginForm.submit.disabled = false;
        console.log(error);
    });
}

createForm.onsubmit = event => {
    event.preventDefault();

    const password = createPassword.value;
    if (password !== createPasswordConfirm.value) {
        createPasswordConfirm.setCustomValidity("Password does not match");
        createPasswordConfirm.reportValidity();
        return;
    }
    const username = createUsername.value;
    const createJson = JSON.stringify({username: username, password: password});
    createForm.submit.disabled = true;
    post("/api/create-account", createJson).then(response => {
        if (!response.ok) {
            if (response.status === 409) {
                createUsername.setCustomValidity("Username is already taken");
                createUsername.reportValidity();
            }
            return Promise.reject(new Error(response.status));
        }
        createFormContent.hidden = true;
        createForm.reset();
        createForm.submit.disabled = false;
        loggedOutButtons.hidden = false;
        login(username, password);
    }).catch(error => {
        createForm.submit.disabled = false;
        console.log(error);
    });
};

document.getElementById("login").onclick = () => {
    loggedOutButtons.hidden = true;
    loginForm.hidden = false;
};

loginForm.onsubmit = event => {
    event.preventDefault();

    loginForm.submit.disabled = true;
    login(loginUsername.value, loginPassword.value);
};

for (const cancel of document.getElementsByClassName("cancel")) {
    cancel.onclick = function() {
        if (createFormContent.contains(this.parentElement)) {
            createFormContent.hidden = true;
        } else {
            this.parentElement.hidden = true;
        }
        this.parentElement.reset();
        loggedOutButtons.hidden = false;
    };
}

for (const logoutButton of document.getElementsByClassName("logout")) {
    logoutButton.onclick = () => {
        logout.disabled = true;
        logoutEverywhere.disabled = true;
        const path = logoutButton === logout ? "/api/logout" : "/api/logout-everywhere";
        post(path).then(response => {
            if (!response.ok) {
                return Promise.reject(new Error(response.status));
            }

            loginStatus.hidden = true;
            devices.innerText = null;
            accountContent.hidden = true;
            username.innerText = null;
            configuration.reset();
            qr.src = "/placeholder.gif";
            qr.alt = "";
            loggedInButtons.hidden = true;
            logout.disabled = false;
            logoutEverywhere.disabled = false;
            loggedOutButtons.hidden = false;
        }).catch(error => {
            logout.disabled = false;
            logoutEverywhere.disabled = false;
            console.log(error);
        });
    };
}

document.getElementById("change_password").onclick = () => {
    loggedInButtons.hidden = true;
    changePasswordForm.current_username.value = username.innerText;
    changePasswordForm.hidden = false;
};

changePasswordForm.onsubmit = event => {
    event.preventDefault();

    const newPassword = changePasswordForm.new_password.value;
    if (newPassword !== changePasswordForm.new_password_confirm.value) {
        changePasswordForm.new_password_confirm.setCustomValidity("Password does not match");
        changePasswordForm.new_password_confirm.reportValidity();
        return;
    }
    const currentPassword = changePasswordForm.current_password.value;
    if (newPassword === currentPassword) {
        changePasswordForm.new_password.setCustomValidity("New password should be different");
        changePasswordForm.new_password.reportValidity();
        return;
    }

    changePasswordForm.submit.disabled = true;
    const data = JSON.stringify({
        "currentPassword": currentPassword,
        "newPassword": newPassword
    });
    post("/api/change-password", data).then(response => {
        if (!response.ok) {
            return Promise.reject(new Error(response.status));
        }
        changePasswordForm.hidden = true;
        changePasswordForm.reset();
        changePasswordForm.submit.disabled = false;
        loggedInButtons.hidden = false;
    }).catch(error => {
        changePasswordForm.submit.disabled = false;
        console.log(error);
    });
};

for (const cancel of document.getElementsByClassName("cancel_account")) {
    cancel.onclick = function() {
        this.parentElement.hidden = true;
        this.parentElement.reset();
        loggedInButtons.hidden = false;
    };
}

rotate.onclick = () => {
    if (confirm("Are you sure you want to rotate the device subscription key? This will not break existing pairings, but will prevent pairing with previous subscription QR codes.")) {
        rotate.disabled = true;
        post("/api/rotate").then(response => {
            if (!response.ok) {
                return Promise.reject(new Error(response.status));
            }
            rotate.disabled = false;
            reloadQrCode();
        }).catch(error => {
            rotate.disabled = false;
            console.log(error);
        });
    }
};

configuration.onsubmit = event => {
    event.preventDefault();

    const verifyInterval = parseInt(configuration.verify_interval.value);
    const alertDelay = parseInt(configuration.alert_delay.value);

    if (alertDelay <= verifyInterval) {
        configuration.alert_delay.setCustomValidity("Alert delay must be larger than verify interval");
        configuration.alert_delay.reportValidity();
        return;
    }

    configuration.submit.disabled = true;
    const data = JSON.stringify({
        "verifyInterval": verifyInterval * 60 * 60,
        "alertDelay": alertDelay * 60 * 60,
        "email": configuration.email.value
    });
    post("/api/configuration", data).then(response => {
        if (!response.ok) {
            return Promise.reject(new Error(response.status));
        }
        configuration.submit.disabled = false;
        reloadQrCode();
    }).catch(error => {
        configuration.submit.disabled = false;
        console.log(error);
    });
};

// @license-end
