from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from typing import Optional, Any, Dict, List
import hashlib

from CTFd.models import db
from CTFd.models import Challenges


def generate_flag_hash(flag: str) -> str:
    """
    Generate a hash of a flag for more efficient lookups
    
    Args:
        flag: The flag to hash
        
    Returns:
        SHA-256 hash of the flag as a hex string
    """
    return hashlib.sha256(flag.encode()).hexdigest()


class ContainerChallengeModel(Challenges):
    """
    Model for container-based challenges that extend standard CTFd challenges
    
    Adds Docker container configuration and dynamic scoring features
    """
    __tablename__ = "container_challenge"
    __mapper_args__ = {"polymorphic_identity": "container"}
    
    id = db.Column(
        db.Integer, db.ForeignKey("challenges.id", ondelete="CASCADE"), primary_key=True
    )
    
    # Docker configuration
    image = db.Column(db.Text, nullable=False)
    port = db.Column(db.Integer, nullable=False)
    command = db.Column(db.Text, default="")
    volumes = db.Column(db.Text, default="")
    connection_type = db.Column(db.Text, default="http")

    # Dynamic challenge properties
    initial = db.Column(db.Integer, default=0)
    minimum = db.Column(db.Integer, default=0)
    decay = db.Column(db.Integer, default=0)

    # Flag configuration
    flag_mode = db.Column(db.Text, default="static")
    random_flag_length = db.Column(db.Integer, default=10)
    flag_prefix = db.Column(db.Text, default="CTF{")
    flag_suffix = db.Column(db.Text, default="}")

    def __init__(self, **kwargs) -> None:
        """
        Initialize container challenge with provided values
        
        Args:
            **kwargs: Challenge properties
        """
        super(ContainerChallengeModel, self).__init__(**kwargs)
        self.value = kwargs.get("initial", 0)

    def __repr__(self) -> str:
        return f"<ContainerChallenge {self.id} '{self.name}'>"


class ContainerInfoModel(db.Model):
    """
    Model for tracking running containers and their association with users/teams
    """
    __tablename__ = "container_info_model"
    __mapper_args__ = {"polymorphic_identity": "container_info"}
    
    container_id = db.Column(db.String(512), primary_key=True)
    challenge_id = db.Column(
        db.Integer, 
        db.ForeignKey("challenges.id", ondelete="CASCADE"), 
        index=True, 
        nullable=False
    )
    team_id = db.Column(
        db.Integer, 
        db.ForeignKey("teams.id", ondelete="CASCADE"), 
        index=True, 
        nullable=True
    )
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"), 
        index=True, 
        nullable=True
    )
    port = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.Integer, nullable=False)
    expires = db.Column(db.Integer, nullable=False)
    flag = db.Column(db.Text, default="")
    
    # Relationships
    team = relationship("Teams", foreign_keys=[team_id])
    user = relationship("Users", foreign_keys=[user_id])
    challenge = relationship(ContainerChallengeModel, foreign_keys=[challenge_id])

    def __repr__(self) -> str:
        owner = f"team:{self.team_id}" if self.team_id else f"user:{self.user_id}"
        return f"<Container {self.container_id[:8]} for challenge {self.challenge_id} ({owner})>"


class ContainerSettingsModel(db.Model):
    """
    Model for storing plugin configuration settings
    """
    __tablename__ = "container_settings_model"
    __mapper_args__ = {"polymorphic_identity": "container_settings"}
    
    key = db.Column(db.String(512), primary_key=True)
    value = db.Column(db.Text)

    def __repr__(self) -> str:
        return f"<ContainerSetting {self.key}>"


class ContainerFlagModel(db.Model):
    """
    Model for tracking container flags and their associations
    
    Supports both static and randomly generated flags
    """
    __tablename__ = "container_flag_model"
    __mapper_args__ = {"polymorphic_identity": "container_flags"}
    
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    challenge_id = db.Column(
        db.Integer, 
        db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False,
        index=True
    )
    container_id = db.Column(
        db.String(512),
        db.ForeignKey("container_info_model.container_id"),
        nullable=True,
        index=True
    )
    flag = db.Column(db.Text, nullable=False)
    flag_hash = db.Column(db.String(64), nullable=False, index=True, unique=True)
    user_id = db.Column(
        db.Integer, 
        db.ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    team_id = db.Column(
        db.Integer, 
        db.ForeignKey("teams.id", ondelete="CASCADE"),
        nullable=True,
        index=True
    )
    used = db.Column(db.Boolean, default=False, index=True)
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationships
    container = relationship(ContainerInfoModel, foreign_keys=[container_id])
    challenge = relationship(ContainerChallengeModel, foreign_keys=[challenge_id])
    user = relationship("Users", foreign_keys=[user_id])
    team = relationship("Teams", foreign_keys=[team_id])

    def __init__(self, **kwargs):
        """
        Initialize a container flag, automatically generating the flag hash
        """
        if "flag" in kwargs:
            kwargs["flag_hash"] = generate_flag_hash(kwargs["flag"])
        super(ContainerFlagModel, self).__init__(**kwargs)

    def __repr__(self) -> str:
        status = "used" if self.used else "unused"
        return f"<ContainerFlag {self.id} for challenge {self.challenge_id} ({status})>"


class ContainerCheatLog(db.Model):
    """
    Model for logging potential cheating attempts
    
    Records when users try to submit flags belonging to other users/teams
    """
    __tablename__ = "container_cheat_logs"
    __mapper_args__ = {"polymorphic_identity": "container_cheat_logs"}

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)

    # The reused flag
    reused_flag = db.Column(db.Text, nullable=False)

    # Which challenge was it from?
    challenge_id = db.Column(
        db.Integer, 
        db.ForeignKey("challenges.id", ondelete="CASCADE"),
        nullable=False
    )
    
    # We'll store the relevant relationships if needed
    challenge = db.relationship("ContainerChallengeModel", foreign_keys=[challenge_id])

    # Original owners
    original_team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    original_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # The second submitter who tried reusing the flag
    second_team_id = db.Column(db.Integer, db.ForeignKey("teams.id"), nullable=True)
    second_user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Time of the cheating attempt
    timestamp = db.Column(db.Integer, nullable=False)

    # Relationship to help retrieve team/user if needed
    original_team = db.relationship("Teams", foreign_keys=[original_team_id])
    original_user = db.relationship("Users", foreign_keys=[original_user_id])
    second_team = db.relationship("Teams", foreign_keys=[second_team_id])
    second_user = db.relationship("Users", foreign_keys=[second_user_id])

    def __repr__(self) -> str:
        return f"<CheatLog {self.id} for challenge {self.challenge_id} at {self.timestamp}>"
