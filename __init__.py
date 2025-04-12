from __future__ import division

import time
import json
import datetime
import math
import logging
from typing import Dict, Any, Optional

from flask import Blueprint, request, Flask, render_template, url_for, redirect, flash

from CTFd.models import db, Solves, Teams, Users
from CTFd.plugins import register_plugin_assets_directory
from CTFd.plugins.challenges import CHALLENGE_CLASSES, BaseChallenge
from CTFd.utils.modes import get_model
from .models import ContainerChallengeModel, ContainerInfoModel, ContainerSettingsModel, ContainerFlagModel, ContainerCheatLog  
from .container_manager import ContainerManager, ContainerException
from .admin_routes import admin_bp, set_container_manager as set_admin_manager
from .user_routes import containers_bp, set_container_manager as set_user_manager
from .helpers import (
    get_settings_path, 
    settings_to_dict, 
    get_xid_and_flag, 
    get_active_container, 
    get_container_flag
)
from CTFd.utils.user import get_current_user
from .migrations import upgrade_flag_model

# Set up logging
logger = logging.getLogger(__name__)

# Load settings
try:
    settings = json.load(open(get_settings_path()))
except (json.JSONDecodeError, FileNotFoundError) as e:
    logger.error(f"Failed to load settings: {e}")
    settings = {
        "plugin-info": {
            "id": "container",
            "name": "Container Challenge",
            "templates": {},
            "scripts": {},
            "base_path": "/containers"
        },
        "blueprint": {
            "template_folder": "templates",
            "static_folder": "assets"
        }
    }

class ContainerChallenge(BaseChallenge):
    """
    Container challenge plugin for CTFd
    
    Allows creation of Docker container-based challenges with dynamic point values
    and flag generation.
    """
    id = settings["plugin-info"]["id"]
    name = settings["plugin-info"]["name"]
    templates = settings["plugin-info"]["templates"]
    scripts = settings["plugin-info"]["scripts"]
    route = settings["plugin-info"]["base_path"]

    challenge_model = ContainerChallengeModel

    @classmethod
    def read(cls, challenge: ContainerChallengeModel) -> Dict[str, Any]:
        """
        Access the data of a challenge in a format processable by the front end.

        Args:
            challenge: Challenge model instance
            
        Returns:
            Dictionary with challenge data
        """
        data = {
            "id": challenge.id,
            "name": challenge.name,
            "value": challenge.value,
            "image": challenge.image,
            "port": challenge.port,
            "command": challenge.command,
            "connection_type": challenge.connection_type,
            "initial": challenge.initial,
            "decay": challenge.decay,
            "minimum": challenge.minimum,
            "description": challenge.description,
            "connection_info": challenge.connection_info,
            "category": challenge.category,
            "state": challenge.state,
            "max_attempts": challenge.max_attempts,
            "type": challenge.type,
            "type_data": {
                "id": cls.id,
                "name": cls.name,
                "templates": cls.templates,
                "scripts": cls.scripts,
            },
        }
        return data

    @classmethod
    def calculate_value(cls, challenge: ContainerChallengeModel) -> ContainerChallengeModel:
        """
        Calculate the dynamic value of a challenge based on solve count
        
        Args:
            challenge: Challenge model instance
            
        Returns:
            Updated challenge model
        """
        Model = get_model()

        solve_count = (
            Solves.query.join(Model, Solves.account_id == Model.id)
            .filter(
                Solves.challenge_id == challenge.id,
                Model.hidden == False,
                Model.banned == False,
            )
            .count()
        )

        # If the solve count is 0 we shouldn't manipulate the solve count to
        # let the math update back to normal
        if solve_count != 0:
            # We subtract -1 to allow the first solver to get max point value
            solve_count -= 1

        # It is important that this calculation takes into account floats.
        # Hence this file uses from __future__ import division
        value = (
            ((challenge.minimum - challenge.initial) / (challenge.decay**2))
            * (solve_count**2)
        ) + challenge.initial

        value = math.ceil(value)

        if value < challenge.minimum:
            value = challenge.minimum

        challenge.value = value
        db.session.commit()
        return challenge

    @classmethod
    def update(cls, challenge: ContainerChallengeModel, request) -> ContainerChallengeModel:
        """
        Update challenge information from request data
        
        Args:
            challenge: Challenge model to update
            request: HTTP request with form or JSON data
            
        Returns:
            Updated challenge model
        """
        data = request.form or request.get_json()

        for attr, value in data.items():
            # We need to set these to floats so that the next operations don't operate on strings
            if attr in ("initial", "minimum", "decay"):
                try:
                    value = float(value)
                except (ValueError, TypeError):
                    logger.warning(f"Invalid value for {attr}: {value}")
                    continue
            setattr(challenge, attr, value)

        return ContainerChallenge.calculate_value(challenge)

    @classmethod
    def solve(cls, user: Users, team: Optional[Teams], challenge: ContainerChallengeModel, request) -> None:
        """
        Handle challenge solve event
        
        Args:
            user: User who solved the challenge
            team: Team the user belongs to (if any)
            challenge: Solved challenge model
            request: HTTP request
        """
        super().solve(user, team, challenge, request)
        cls.calculate_value(challenge)

    @classmethod
    def attempt(cls, challenge: ContainerChallengeModel, request) -> tuple:
        """
        Handle flag submission attempt
        
        Args:
            challenge: Challenge being attempted
            request: HTTP request with flag submission
            
        Returns:
            Tuple of (success, message)
        """
        # 1) Gather user/team & submitted_flag
        try:
            user, x_id, submitted_flag = get_xid_and_flag()
        except ValueError as e:
            return False, str(e)

        # 2) Get running container
        container_info = None
        try:
            container_info = get_active_container(challenge.id, x_id)
        except ValueError as e:
            return False, str(e)

        # 3) Check if container is actually running
        global container_manager
        if not container_manager or not container_manager.is_container_running(container_info.container_id):
            return False, "Your container is not running; you cannot submit yet."

        # 4) Validate the flag belongs to the user/team
        try:
            container_flag = get_container_flag(submitted_flag, user, container_manager, container_info, challenge)
        except ValueError as e:
            return False, str(e)  # Return incorrect flag message if not cheating

        # 5) Mark flag as used
        container_flag.used = True
        db.session.commit()
        
        logger.info(f"Correct flag submitted for challenge {challenge.id} by {'team' if team else 'user'} {x_id}")

        # 6) Clean up based on challenge mode
        if challenge.flag_mode == "static":
            # If static challenge, delete both flag and container records
            db.session.delete(container_flag)
            db.session.commit()
            logger.debug(f"Static flag deleted for challenge {challenge.id}")
        
        elif challenge.flag_mode == "random":
            # If random challenge, keep the flag but remove container reference
            db.session.query(ContainerFlagModel).filter_by(
                container_id=container_info.container_id
            ).update({"container_id": None})
            db.session.commit()
            logger.debug(f"Container reference removed from flag for challenge {challenge.id}")

        # 7) Remove container info and kill container
        container = ContainerInfoModel.query.filter_by(container_id=container_info.container_id).first()
        if container:
            db.session.delete(container)
            db.session.commit()

        try:
            container_manager.kill_container(container_info.container_id)
            logger.info(f"Container {container_info.container_id} killed after successful solve")
        except ContainerException as e:
            logger.error(f"Failed to kill container after solve: {e}")

        return True, "Correct"


# Global container manager instance
container_manager = None


def load(app: Flask) -> None:
    """
    Initialize the plugin
    
    Args:
        app: Flask application instance
    """
    # Ensure database is initialized
    app.db.create_all()
    logger.info("Container challenge plugin initializing")

    # Register the challenge type
    CHALLENGE_CLASSES["container"] = ContainerChallenge
    logger.debug("Container challenge type registered")

    # Run database migrations if needed
    with app.app_context():
        try:
            if upgrade_flag_model():
                logger.info("Database migration completed successfully")
        except Exception as e:
            logger.error(f"Error during database migration: {e}")

    # Register static assets
    register_plugin_assets_directory(
        app, base_path=settings["plugin-info"]["base_path"]
    )

    # Initialize container manager
    try:
        global container_manager
        container_settings = settings_to_dict(ContainerSettingsModel.query.all())
        container_manager = ContainerManager(container_settings, app)
        
        if container_manager.is_connected():
            logger.info("Container manager connected to Docker successfully")
        else:
            logger.warning("Container manager failed to connect to Docker")
    except Exception as e:
        logger.error(f"Failed to initialize container manager: {e}")

    # Create base blueprint
    base_bp = Blueprint(
        "containers",
        __name__,
        template_folder=settings["blueprint"]["template_folder"],
        static_folder=settings["blueprint"]["static_folder"]
    )

    # Share container manager with route modules
    set_admin_manager(container_manager)
    set_user_manager(container_manager)

    # Register blueprints
    app.register_blueprint(admin_bp)     # Admin APIs
    app.register_blueprint(containers_bp) # User APIs
    app.register_blueprint(base_bp)       # Base routes
    
    logger.info("Container challenge plugin initialized successfully")
