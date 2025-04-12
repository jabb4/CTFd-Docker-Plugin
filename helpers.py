import os
import json
import time
import logging
from typing import Dict, List, Tuple, Optional, Any, Union

from flask import jsonify, request, Response
from CTFd.utils import get_config
from .models import ContainerChallengeModel, ContainerInfoModel, ContainerSettingsModel, ContainerFlagModel, ContainerCheatLog, generate_flag_hash
from .container_manager import ContainerManager, ContainerException
from CTFd.models import db, Teams, Users, Solves
from CTFd.utils.user import get_current_user

# Set up logging
logger = logging.getLogger(__name__)

def get_settings_path() -> str:
    """
    Retrieve the path to settings.json
    
    Returns:
        Absolute path to the settings.json file
    """
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "settings.json")


# Load settings once on module import
settings = json.load(open(get_settings_path()))
USERS_MODE = settings["modes"]["USERS_MODE"]
TEAMS_MODE = settings["modes"]["TEAMS_MODE"]


def settings_to_dict(settings: List[ContainerSettingsModel]) -> Dict[str, str]:
    """
    Convert settings table records into a dictionary
    
    Args:
        settings: List of ContainerSettingsModel objects
        
    Returns:
        Dictionary with key-value pairs from settings
    """
    return {setting.key: setting.value for setting in settings}


def is_team_mode() -> bool:
    """
    Determine if CTF is running in team mode
    
    Returns:
        True if in team mode, False otherwise
    """
    mode = get_config("user_mode")
    return mode == TEAMS_MODE


def kill_container(container_manager: ContainerManager, container_id: str) -> Response:
    """
    Kill and remove a running container
    
    Args:
        container_manager: Container manager instance
        container_id: ID of container to kill
        
    Returns:
        JSON response indicating success or error
    """
    container = ContainerInfoModel.query.filter_by(container_id=container_id).first()

    if not container:
        return jsonify({"error": "Container not found"}), 400

    try:
        # Kill container in Docker
        container_manager.kill_container(container_id)
        
        # Find all related flag records
        challenge = container.challenge
        flag_records = ContainerFlagModel.query.filter_by(container_id=container_id).all()
        
        # Handle flags based on challenge mode
        if challenge and challenge.flag_mode == "static":
            # Remove all flags for static-mode challenges
            for flag in flag_records:
                db.session.delete(flag)
        else:
            # For random flags, keep used ones but remove container reference
            for flag in flag_records:
                if flag.used:
                    flag.container_id = None
                else:
                    db.session.delete(flag)
                    
        # Remove container record
        db.session.delete(container)
        db.session.commit()
        
        logger.info(f"Container {container_id} killed and records cleaned up")
        return jsonify({"success": "Container killed"})
        
    except ContainerException as e:
        logger.error(f"Failed to kill container {container_id}: {e}")
        return jsonify({"error": f"Docker error: {str(e)}"}), 500


def renew_container(container_manager: ContainerManager, chal_id: int, xid: int, is_team: bool) -> Response:
    """
    Extend the expiration time of an active container
    
    Args:
        container_manager: Container manager instance
        chal_id: Challenge ID
        xid: User or team ID
        is_team: Whether xid is a team ID
        
    Returns:
        JSON response with updated container info or error
    """
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()

    if not challenge:
        return jsonify({"error": "Challenge not found"}), 400

    running_container = ContainerInfoModel.query.filter_by(
        challenge_id=challenge.id,
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).first()

    if not running_container:
        return jsonify({"error": "Container not found, try resetting the container."}), 404

    try:
        # Verify container is still running
        if not container_manager.is_container_running(running_container.container_id):
            return jsonify({"error": "Container is no longer running. Please start a new one."}), 400
            
        # Update expiration time
        running_container.expires = int(time.time() + container_manager.expiration_seconds)
        db.session.commit()
        
        logger.info(f"Container {running_container.container_id} renewed until {running_container.expires}")
        
        return jsonify({
            "success": "Container renewed",
            "expires": running_container.expires,
            "hostname": container_manager.settings.get("docker_hostname", ""),
            "port": running_container.port,
            "connect": challenge.connection_type,
        })
    except ContainerException as e:
        logger.error(f"Error renewing container: {e}")
        return jsonify({"error": f"Docker error: {str(e)}"}), 500
    except Exception as e:
        logger.error(f"Database error: {e}")
        return jsonify({"error": "Database error occurred, please try again."}), 500


def create_container(container_manager: ContainerManager, chal_id: int, xid: int, is_team: bool) -> Response:
    """
    Create a new challenge container
    
    Args:
        container_manager: Container manager instance
        chal_id: Challenge ID
        xid: User or team ID
        is_team: Whether xid is a team ID
        
    Returns:
        JSON response with container info or error
    """
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()

    if not challenge:
        return jsonify({"error": "Challenge not found"}), 400

    # Check if challenge is already solved
    if Solves.query.filter_by(challenge_id=chal_id, account_id=xid).first():
        return jsonify({"error": "Challenge already solved"}), 400

    # Get max container limit from settings
    try:
        max_containers = int(container_manager.settings.get("max_containers", 3))
    except (ValueError, TypeError):
        max_containers = 3  # Default if setting is invalid

    # Check for existing container for this challenge
    running_container = ContainerInfoModel.query.filter_by(
        challenge_id=challenge.id,
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).first()

    # Count total containers for this user/team
    container_count = ContainerInfoModel.query.filter_by(
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).count()

    # Check if user/team has reached the max container limit
    if container_count >= max_containers and not running_container:
        return jsonify({
            "error": f"Max containers ({max_containers}) reached. Please stop a running container before starting a new one."
        }), 400

    # Check if there's already a running container for this challenge
    if running_container:
        try:
            if container_manager.is_container_running(running_container.container_id):
                return jsonify({
                    "status": "already_running",
                    "hostname": container_manager.settings.get("docker_hostname", ""),
                    "port": running_container.port,
                    "connect": challenge.connection_type,
                    "expires": running_container.expires,
                })
            else:
                # Container exists in DB but not running - clean up
                logger.info(f"Found stale container {running_container.container_id} - cleaning up")
                db.session.delete(running_container)
                db.session.commit()
        except ContainerException as e:
            logger.error(f"Error checking container status: {e}")
            return jsonify({"error": str(e)}), 500

    # Start a new Docker container
    try:
        created_container = container_manager.create_container(challenge, xid, is_team)
        logger.info(f"Created new container for challenge {chal_id}, user/team {xid}")
        
        return jsonify({
            "status": "created",
            "hostname": container_manager.settings.get("docker_hostname", ""),
            "port": created_container["port"],
            "connect": challenge.connection_type,
            "expires": created_container["expires"],
        })
    except ContainerException as e:
        logger.error(f"Failed to create container: {e}")
        return jsonify({"error": str(e)}), 500


def view_container_info(container_manager: ContainerManager, chal_id: int, xid: int, is_team: bool) -> Response:
    """
    Retrieve information about a running container
    
    Args:
        container_manager: Container manager instance
        chal_id: Challenge ID
        xid: User or team ID
        is_team: Whether xid is a team ID
        
    Returns:
        JSON response with container info or status
    """
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()

    if not challenge:
        return jsonify({"error": "Challenge not found"}), 400

    running_container = ContainerInfoModel.query.filter_by(
        challenge_id=challenge.id,
        team_id=xid if is_team else None,
        user_id=None if is_team else xid,
    ).first()

    if running_container:
        try:
            if container_manager.is_container_running(running_container.container_id):
                return jsonify({
                    "status": "already_running",
                    "hostname": container_manager.settings.get("docker_hostname", ""),
                    "port": running_container.port,
                    "connect": challenge.connection_type,
                    "expires": running_container.expires,
                })
            else:
                # Container exists in DB but not running anymore - clean up
                logger.info(f"Found stale container {running_container.container_id} - cleaning up")
                db.session.delete(running_container)
                db.session.commit()
                return jsonify({"status": "not_running"})
        except ContainerException as e:
            logger.error(f"Error checking container status: {e}")
            return jsonify({"error": str(e)}), 500
    else:
        return jsonify({"status": "not_started"})


def connect_type(chal_id: int) -> Response:
    """
    Get the connection type for a challenge
    
    Args:
        chal_id: Challenge ID
        
    Returns:
        JSON response with connection type or error
    """
    challenge = ContainerChallengeModel.query.filter_by(id=chal_id).first()

    if not challenge:
        return jsonify({"error": "Challenge not found"}), 400

    return jsonify({"status": "ok", "connect": challenge.connection_type})


def get_xid_and_flag() -> Tuple[Users, int, str]:
    """
    Get user/team ID and submitted flag from the current request
    
    Returns:
        Tuple of (user object, user/team ID, submitted flag)
        
    Raises:
        ValueError: If missing required data or user is not authenticated
    """
    user = get_current_user()
    if not user:
        raise ValueError("You must be logged in to attempt this challenge.")

    if is_team_mode():
        if not user.team_id:
            raise ValueError("You must belong to a team to solve this challenge.")
        x_id = user.team_id
    else:
        x_id = user.id

    # Parse flag from JSON or form
    data = request.get_json() or request.form
    submitted_flag = data.get("submission", "").strip()
    if not submitted_flag:
        raise ValueError("No flag provided.")

    return user, x_id, submitted_flag


def get_active_container(challenge_id: int, x_id: int) -> ContainerInfoModel:
    """
    Get active container for a challenge and user/team
    
    Args:
        challenge_id: Challenge ID
        x_id: User or team ID
        
    Returns:
        ContainerInfoModel object
        
    Raises:
        ValueError: If no active container found
    """
    container_info = ContainerInfoModel.query.filter_by(
        challenge_id=challenge_id,
        team_id=x_id if is_team_mode() else None,
        user_id=None if is_team_mode() else x_id,
    ).first()

    if not container_info:
        raise ValueError("No container is currently active for this challenge.")

    return container_info


def get_container_flag(submitted_flag: str, user: Users, container_manager: ContainerManager, 
                      container_info: ContainerInfoModel, challenge: ContainerChallengeModel) -> ContainerFlagModel:
    """
    Validate a submitted flag against container flags
    
    Args:
        submitted_flag: Flag submitted by user
        user: Current user object
        container_manager: Container manager instance
        container_info: Container info object
        challenge: Challenge object
        
    Returns:
        ContainerFlagModel object if valid
        
    Raises:
        ValueError: If flag is invalid or user is trying to cheat
    """
    # Generate hash from submitted flag for secure lookup
    submitted_flag_hash = generate_flag_hash(submitted_flag)
    
    # Get current user/team ID
    x_id = user.team_id if is_team_mode() else user.id
    is_team = is_team_mode()
    
    # First query: Check if flag exists for this challenge with the correct owner
    # This optimized query checks all relevant conditions at once, reducing DB calls
    container_flag = ContainerFlagModel.query.filter(
        ContainerFlagModel.flag_hash == submitted_flag_hash,
        ContainerFlagModel.challenge_id == challenge.id,
        (ContainerFlagModel.team_id == x_id if is_team else ContainerFlagModel.user_id == x_id),
        ContainerFlagModel.used == False
    ).first()
    
    if container_flag:
        # Valid flag found, return it
        return container_flag
    
    # If we're here, either the flag doesn't exist, belongs to another user/team, or was already used
    
    # Check if flag exists at all (might be for another user/team - potential cheating)
    cheat_check_flag = ContainerFlagModel.query.filter_by(flag_hash=submitted_flag_hash).first()
    
    if cheat_check_flag:
        # Flag exists but belongs to someone else or is already used
        
        # Check if flag belongs to this user/team but was already used
        if ((is_team and cheat_check_flag.team_id == x_id) or 
            (not is_team and cheat_check_flag.user_id == x_id)):
            raise ValueError("This flag has already been used.")
            
        # Flag belongs to another user/team - log cheating attempt
        log_cheating_attempt(cheat_check_flag, user)
        
        # Add a small delay to prevent timing attacks that could reveal valid flags
        time.sleep(0.5)
        
        # Return generic error to avoid leaking information
        raise ValueError("The provided flag is incorrect.")
    
    # Flag doesn't exist at all
    raise ValueError("The provided flag is incorrect.")


def log_cheating_attempt(container_flag: ContainerFlagModel, second_user: Users) -> None:
    """
    Log details of a user trying to use another user's flag
    
    Args:
        container_flag: The flag that was attempted to be used
        second_user: The user who tried to use someone else's flag
    """
    try:
        # Get original owner info
        is_team = is_team_mode()
        
        cheat_log = ContainerCheatLog(
            reused_flag=container_flag.flag,
            challenge_id=container_flag.challenge_id,
            original_team_id=container_flag.team_id if is_team else None,
            original_user_id=container_flag.user_id if not is_team else None,
            second_team_id=second_user.team_id if is_team else None,
            second_user_id=second_user.id if not is_team else None,
            timestamp=int(time.time())
        )
        
        db.session.add(cheat_log)
        db.session.commit()
        
        logger.warning(
            f"CHEATING ATTEMPT: User {second_user.id} tried to use flag from "
            f"{'team ' + str(container_flag.team_id) if is_team else 'user ' + str(container_flag.user_id)}"
        )
    except Exception as e:
        logger.error(f"Failed to log cheating attempt: {e}")


def get_current_user_or_team() -> int:
    """
    Get current user or team ID
    
    Returns:
        User ID or team ID depending on CTF mode
    """
    user = get_current_user()
    if is_team_mode():
        return user.team_id
    return user.id


def validate_request(json_data: Optional[Dict], required_fields: List[str]) -> None:
    """
    Validate that a request contains all required fields
    
    Args:
        json_data: JSON data from request
        required_fields: List of required field names
        
    Raises:
        ValueError: If any required fields are missing
    """
    if not json_data:
        raise ValueError("No data provided")
        
    for field in required_fields:
        if field not in json_data:
            raise ValueError(f"Missing required field: {field}")