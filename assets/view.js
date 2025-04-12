CTFd._internal.challenge.data = undefined;
CTFd._internal.challenge.renderer = null;
CTFd._internal.challenge.preRender = function () {};
CTFd._internal.challenge.render = null;
CTFd._internal.challenge.postRender = function () {};

CTFd._internal.challenge.submit = function (preview) {
    var challenge_id = parseInt(CTFd.lib.$("#challenge-id").val());
    var submission = CTFd.lib.$("#challenge-input").val();

    let alert = resetAlert();

    var body = {
        challenge_id: challenge_id,
        submission: submission,
    };
    var params = {};
    if (preview) {
        params["preview"] = true;
    }

    return CTFd.api
        .post_challenge_attempt(params, body)
        .then(function (response) {
            if (response.status === 429) return response; // Rate limit
            if (response.status === 403) return response; // Not logged in / CTF paused
            return response;
        });
};

function mergeQueryParams(parameters, queryParameters) {
    if (parameters.$queryParameters) {
        Object.keys(parameters.$queryParameters).forEach(function (parameterName) {
            queryParameters[parameterName] = parameters.$queryParameters[parameterName];
        });
    }
    return queryParameters;
}

function resetAlert() {
    let alert = document.getElementById("deployment-info");
    alert.innerHTML = '<div class="spinner-border text-primary" role="status"><span class="visually-hidden">Loading...</span></div>';
    alert.classList.remove("alert-danger");

    // Disable buttons while loading
    document.getElementById("create-chal").disabled = true;
    document.getElementById("extend-chal").disabled = true;
    document.getElementById("terminate-chal").disabled = true;

    return alert;
}

function enableButtons() {
    document.getElementById("create-chal").disabled = false;
    document.getElementById("extend-chal").disabled = false;
    document.getElementById("terminate-chal").disabled = false;
}

function toggleChallengeCreate() {
    document.getElementById("create-chal").classList.toggle('d-none');
}

function toggleChallengeUpdate() {
    document.getElementById("extend-chal").classList.toggle('d-none');
    document.getElementById("terminate-chal").classList.toggle('d-none');
}

function calculateExpiry(timestamp) {
    if (!timestamp) return 'Unknown';
    
    // Convert timestamp to milliseconds if it's in seconds
    const timestampMs = timestamp * 1000;
    const expiryDate = new Date(timestampMs);
    const now = new Date();
    
    // Calculate the difference in minutes
    const diffMs = expiryDate - now;
    if (diffMs <= 0) return 'Expired';
    
    const diffMinutes = Math.ceil(diffMs / 1000 / 60);
    return diffMinutes;
}

function createChallengeLinkElement(data, parent) {
    parent.innerHTML = "";
    
    // Enable debugging to see what data is actually received
    console.log("Container data received:", data);
    
    // Check if all required data is present
    if (!data) {
        parent.innerHTML = "No container data received. Please try again.";
        parent.classList.add("alert-danger");
        return;
    }
    
    // Use default values for missing fields to avoid undefined errors
    const hostname = data.hostname || "localhost";
    const port = data.port || "N/A";
    const expires = data.expires || 0;
    const connectionType = data.connect || "http";
    
    // Calculate expiry time
    const expiryMinutes = calculateExpiry(expires);
    
    // Show expires information
    let expiresElement = document.createElement('span');
    expiresElement.textContent = "Expires in " + expiryMinutes + " minutes.";
    parent.append(expiresElement, document.createElement('br'));

    // Create connection information based on connection type
    if (connectionType === "tcp") {
        let codeElement = document.createElement('code');
        codeElement.textContent = 'nc ' + hostname + " " + port;
        parent.append(codeElement);
    } else {
        let link = document.createElement('a');
        link.href = 'http://' + hostname + ":" + port;
        link.textContent = 'http://' + hostname + ":" + port;
        link.target = '_blank';
        parent.append(link);
    }
    
    // Make sure parent has the right styling
    parent.classList.remove("alert-danger");
    parent.classList.add("alert-primary");
}

function view_container_info(challenge_id) {
    let alert = resetAlert();

    fetch("/containers/api/view_info", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "CSRF-Token": init.csrfNonce
        },
        body: JSON.stringify({ chal_id: challenge_id })
    })
    .then(response => response.json())
    .then(data => {
        alert.innerHTML = ""; // Remove spinner
        
        if (data.error) {
            alert.innerHTML = data.error;
            alert.classList.add("alert-danger");
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
            return;
        }
        
        if (data.status === "not_started" || data.status === "Challenge not started") {
            alert.innerHTML = "No active instance. Click 'Fetch Instance' to start a new container.";
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
        } else if (data.status === "already_running") {
            createChallengeLinkElement(data, alert);
            document.getElementById("create-chal").classList.add("d-none");
            document.getElementById("extend-chal").classList.remove("d-none");
            document.getElementById("terminate-chal").classList.remove("d-none");
        } else if (data.status === "not_running") {
            alert.innerHTML = "Your instance has stopped. Click 'Fetch Instance' to start a new container.";
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
        } else {
            // Fall back for any other status
            alert.innerHTML = data.status || "Unknown status";
            alert.classList.add("alert-info");
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
        }
    })
    .catch(error => {
        alert.innerHTML = "Error fetching container info.";
        alert.classList.add("alert-danger");
        console.error("Fetch error:", error);
        // In case of error, show the create button
        document.getElementById("create-chal").classList.remove("d-none");
    })
    .finally(enableButtons);
}

function container_request(challenge_id) {
    let alert = resetAlert();

    fetch("/containers/api/request", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "CSRF-Token": init.csrfNonce
        },
        body: JSON.stringify({ chal_id: challenge_id })
    })
    .then(response => response.json())
    .then(data => {
        alert.innerHTML = ""; // Remove spinner
        
        if (data.error) {
            alert.innerHTML = data.error;
            alert.classList.add("alert-danger");
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
            return;
        }
        
        if (data.status === "created" || data.status === "already_running") {
            createChallengeLinkElement(data, alert);
            document.getElementById("create-chal").classList.add("d-none");
            document.getElementById("extend-chal").classList.remove("d-none");
            document.getElementById("terminate-chal").classList.remove("d-none");
        } else {
            // Handle any other status
            alert.innerHTML = data.message || data.status || "Unknown response";
            alert.classList.add("alert-info");
            document.getElementById("create-chal").classList.remove("d-none");
        }
    })
    .catch(error => {
        alert.innerHTML = "Error requesting container.";
        alert.classList.add("alert-danger");
        console.error("Fetch error:", error);
        document.getElementById("create-chal").classList.remove("d-none");
    })
    .finally(enableButtons);
}

function container_renew(challenge_id) {
    let alert = resetAlert();

    fetch("/containers/api/renew", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "CSRF-Token": init.csrfNonce
        },
        body: JSON.stringify({ chal_id: challenge_id })
    })
    .then(response => response.json())
    .then(data => {
        alert.innerHTML = ""; // Remove spinner
        
        if (data.error) {
            alert.innerHTML = data.error;
            alert.classList.add("alert-danger");
            return;
        }
        
        if (data.success) {
            // If the renew was successful, display connection details
            createChallengeLinkElement(data, alert);
        } else if (data.message) {
            // Display any other messages
            alert.innerHTML = data.message;
            alert.classList.add("alert-info");
        } else {
            // Fallback message
            createChallengeLinkElement(data, alert);
        }
    })
    .catch(error => {
        alert.innerHTML = "Error renewing container.";
        alert.classList.add("alert-danger");
        console.error("Fetch error:", error);
    })
    .finally(enableButtons);
}

function container_stop(challenge_id) {
    let alert = resetAlert();

    fetch("/containers/api/stop", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "Accept": "application/json",
            "CSRF-Token": init.csrfNonce
        },
        body: JSON.stringify({ chal_id: challenge_id })
    })
    .then(response => response.json())
    .then(data => {
        alert.innerHTML = ""; // Remove spinner
        
        if (data.error) {
            alert.innerHTML = data.error;
            alert.classList.add("alert-danger");
        } else if (data.success) {
            alert.innerHTML = "Container terminated successfully.";
            // Show create button, hide extend and terminate
            document.getElementById("create-chal").classList.remove("d-none");
            document.getElementById("extend-chal").classList.add("d-none");
            document.getElementById("terminate-chal").classList.add("d-none");
        } else {
            // Handle any unexpected response
            alert.innerHTML = data.message || "Unknown response.";
            alert.classList.add("alert-warning");
        }
    })
    .catch(error => {
        alert.innerHTML = "Error stopping container.";
        alert.classList.add("alert-danger");
        console.error("Fetch error:", error);
    })
    .finally(enableButtons);
}