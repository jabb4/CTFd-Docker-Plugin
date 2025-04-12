import atexit
import time
import json
import secrets  # More secure than random for cryptographic purposes
import string
import logging
from typing import Dict, List, Optional, Any, Tuple, Union, Callable

from flask import Flask, current_app
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.schedulers import SchedulerNotRunningError
import docker
import paramiko.ssh_exception
import requests

from CTFd.models import db
from .models import ContainerInfoModel, ContainerFlagModel

# Set up logging
logger = logging.getLogger(__name__)

def generate_random_flag(challenge: Any) -> str:
    """
    Generate a cryptographically secure random flag
    
    Args:
        challenge: Challenge model containing flag configuration
        
    Returns:
        Generated flag string with prefix and suffix
        
    Raises:
        ValueError: If flag configuration is invalid
    """
    # Validate flag length
    try:
        flag_length = max(1, min(challenge.random_flag_length, 100))  # Limit between 1-100
    except (AttributeError, TypeError):
        flag_length = 10  # Default if not properly configured
        logger.warning(f"Invalid flag length for challenge {getattr(challenge, 'id', 'unknown')}, using default of 10")
    
    # Define character sets for different security levels
    charset_strong = string.ascii_letters + string.digits
    charset_extra_strong = charset_strong + string.punctuation.replace("{", "").replace("}", "")
    
    # Choose character set based on challenge difficulty or settings
    charset = charset_strong
    
    # Generate random part using cryptographically secure method
    try:
        random_part = "".join(
            secrets.choice(charset) for _ in range(flag_length)
        )
    except Exception as e:
        logger.error(f"Error generating random flag: {e}")
        # Fallback generation method
        random_part = "".join(
            secrets.choice(string.ascii_letters + string.digits) for _ in range(10)
        )
    
    # Get prefix and suffix, or use defaults
    prefix = getattr(challenge, "flag_prefix", "CTF{") or "CTF{"
    suffix = getattr(challenge, "flag_suffix", "}") or "}"
    
    return f"{prefix}{random_part}{suffix}"


class ContainerException(Exception):
    """Exception raised for container-related errors"""
    def __init__(self, message: str = None) -> None:
        self.message = message or "Unknown Container Exception"
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


class ContainerManager:
    """Manages Docker containers for challenges"""
    
    def __init__(self, settings: Dict[str, Any], app: Flask) -> None:
        """
        Initialize the container manager with settings
        
        Args:
            settings: Dictionary containing Docker configuration
            app: Flask application instance
        """
        self.settings = settings
        self.client = None
        self.app = app
        self.expiration_scheduler = None
        self.expiration_seconds = 0
        
        if not settings.get("docker_base_url"):
            logger.warning("Docker base URL not configured - container manager disabled")
            return

        # Connect to the docker daemon
        try:
            self.initialize_connection(settings, app)
        except ContainerException as e:
            logger.error(f"Docker initialization failed: {e}")
            return

    def initialize_connection(self, settings: Dict[str, Any], app: Flask) -> None:
        """
        Initialize connection to Docker daemon
        
        Args:
            settings: Dictionary containing Docker configuration
            app: Flask application instance
            
        Raises:
            ContainerException: If connection to Docker fails
        """
        self.settings = settings
        self.app = app

        # Remove any leftover expiration schedulers
        try:
            if self.expiration_scheduler:
                self.expiration_scheduler.shutdown()
        except (SchedulerNotRunningError, AttributeError):
            # Scheduler was never running
            pass

        if not settings.get("docker_base_url"):
            self.client = None
            return

        try:
            self.client = docker.DockerClient(base_url=settings.get("docker_base_url"))
            # Test connection
            self.client.ping()
        except docker.errors.DockerException as e:
            self.client = None
            raise ContainerException(f"CTFd could not connect to Docker: {str(e)}")
        except TimeoutError:
            self.client = None
            raise ContainerException("CTFd timed out when connecting to Docker")
        except paramiko.ssh_exception.NoValidConnectionsError as e:
            self.client = None
            raise ContainerException(f"SSH connection error: {str(e)}")
        except paramiko.ssh_exception.AuthenticationException as e:
            self.client = None
            raise ContainerException(f"SSH authentication error: {str(e)}")
        except Exception as e:
            self.client = None
            raise ContainerException(f"Unexpected error connecting to Docker: {str(e)}")

        # Set up expiration scheduler
        try:
            self.expiration_seconds = int(settings.get("container_expiration", 0)) * 60
        except (ValueError, AttributeError):
            self.expiration_seconds = 0

        if self.expiration_seconds > 0:
            self.expiration_scheduler = BackgroundScheduler()
            self.expiration_scheduler.add_job(
                func=self.kill_expired_containers,
                trigger="interval",
                seconds=5,  # Check every 5 seconds
            )
            self.expiration_scheduler.start()

            # Shut down the scheduler when exiting the app
            atexit.register(lambda: self.expiration_scheduler.shutdown(wait=False))

    def run_command(func: Callable) -> Callable:
        """
        Decorator to handle Docker connection state and errors
        
        Args:
            func: Function to wrap
            
        Returns:
            Wrapped function with error handling
        """
        def wrapper(self, *args, **kwargs):
            if not self.client:
                try:
                    self.initialize_connection(self.settings, self.app)
                    if not self.client:
                        raise ContainerException("Docker is not connected")
                except Exception as e:
                    raise ContainerException(f"Docker connection failed: {str(e)}")
                    
            try:
                # Verify connection is still active
                if not self.client.ping():
                    raise ContainerException("Docker connection lost")
                return func(self, *args, **kwargs)
            except (
                paramiko.ssh_exception.SSHException,
                ConnectionError,
                requests.exceptions.ConnectionError,
                docker.errors.APIError
            ) as e:
                # Try to reconnect before failing
                try:
                    self.initialize_connection(self.settings, self.app)
                except Exception:
                    pass
                raise ContainerException(f"Docker error: {str(e)}")
            except Exception as e:
                raise ContainerException(f"Unexpected error: {str(e)}")
                
        return wrapper

    @run_command
    def kill_expired_containers(self) -> None:
        """Kill all expired containers"""
        with self.app.app_context():
            containers = ContainerInfoModel.query.all()

            for container in containers:
                delta_seconds = container.expires - int(time.time())
                if delta_seconds < 0:
                    try:
                        self.kill_container(container.container_id)
                        logger.info(f"Expired container killed: {container.container_id}")
                    except ContainerException as e:
                        logger.error(f"Failed to kill expired container: {str(e)}")

                    db.session.delete(container)
                    db.session.commit()

    @run_command
    def is_container_running(self, container_id: str) -> bool:
        """
        Check if a container is still running
        
        Args:
            container_id: Docker container ID
            
        Returns:
            True if container is running, False otherwise
        """
        try:
            container = self.client.containers.get(container_id)
            return container.status == "running"
        except docker.errors.NotFound:
            return False

    @run_command
    def create_container(self, challenge, xid, is_team) -> Dict[str, Any]:
        """
        Create a new Docker container for a challenge
        
        Args:
            challenge: Challenge model
            xid: User or team ID
            is_team: Whether xid is a team ID
            
        Returns:
            Dictionary with container info
            
        Raises:
            ContainerException: If container creation fails
        """
        kwargs = {}

        # Generate appropriate flag based on challenge settings
        flag = (
            generate_random_flag(challenge)
            if challenge.flag_mode == "random"
            else challenge.flag_prefix + challenge.flag_suffix
        )

        # Set memory limits
        if self.settings.get("container_maxmemory"):
            try:
                mem_limit = int(self.settings.get("container_maxmemory"))
                if mem_limit > 0:
                    kwargs["mem_limit"] = f"{mem_limit}m"
            except ValueError:
                raise ContainerException("Configured container memory limit must be an integer")
                
        # Set CPU limits
        if self.settings.get("container_maxcpu"):
            try:
                cpu_period = float(self.settings.get("container_maxcpu"))
                if cpu_period > 0:
                    kwargs["cpu_quota"] = int(cpu_period * 100000)
                    kwargs["cpu_period"] = 100000
            except ValueError:
                raise ContainerException("Configured container CPU limit must be a number")

        # Set up volumes if specified
        if challenge.volumes:
            try:
                volumes_dict = json.loads(challenge.volumes)
                kwargs["volumes"] = volumes_dict
            except json.decoder.JSONDecodeError:
                raise ContainerException("Volumes JSON string is invalid")

        try:
            # Create the container
            container = self.client.containers.run(
                challenge.image,
                ports={str(challenge.port): None},
                command=challenge.command,
                detach=True,
                auto_remove=True,
                environment={"FLAG": flag},
                **kwargs,
            )

            # Get assigned port
            port = self.get_container_port(container.id)
            if port is None:
                container.remove(force=True)
                raise ContainerException("Could not get container port")
                
            # Set expiration time
            expires = int(time.time() + self.expiration_seconds)

            # Record container in database
            new_container_entry = ContainerInfoModel(
                container_id=container.id,
                challenge_id=challenge.id,
                team_id=xid if is_team else None,
                user_id=None if is_team else xid,
                port=port,
                flag=flag,
                timestamp=int(time.time()),
                expires=expires,
            )
            db.session.add(new_container_entry)
            
            # Save the flag
            new_flag_entry = ContainerFlagModel(
                challenge_id=challenge.id,
                container_id=container.id,
                flag=flag,
                team_id=xid if is_team else None,
                user_id=None if is_team else xid,
            )
            db.session.add(new_flag_entry)
            db.session.commit()

            logger.info(f"Container created: {container.id} for challenge {challenge.id}")
            return {"container": container, "expires": expires, "port": port}
            
        except docker.errors.ImageNotFound:
            raise ContainerException(f"Docker image {challenge.image} not found")
        except docker.errors.APIError as e:
            raise ContainerException(f"Docker API error: {str(e)}")

    @run_command
    def get_container_port(self, container_id: str) -> Optional[str]:
        """
        Get the exposed port for a container
        
        Args:
            container_id: Docker container ID
            
        Returns:
            Port number as string or None if not found
        """
        container = self.client.containers.get(container_id)
        ports = container.attrs["NetworkSettings"]["Ports"]
        for port in ports:
            if ports[port] and len(ports[port]) > 0:
                return ports[port][0]["HostPort"]
        return None

    @run_command
    def get_images(self) -> List[str]:
        """
        Get list of available Docker images
        
        Returns:
            List of image names
        """
        images = []
        for image in self.client.images.list():
            if image.tags:
                for tag in image.tags:
                    images.append(tag)
        
        # Sort alphabetically for easier use
        images.sort()
        return images

    @run_command
    def kill_container(self, container_id: str) -> None:
        """
        Kill and remove a Docker container
        
        Args:
            container_id: Docker container ID
            
        Raises:
            ContainerException: If container cannot be removed
        """
        try:
            container = self.client.containers.get(container_id)
            container.remove(force=True)
            logger.info(f"Container killed: {container_id}")
        except docker.errors.NotFound:
            # Container may have already been removed
            logger.warning(f"Container not found for removal: {container_id}")
        except docker.errors.APIError as e:
            raise ContainerException(f"Failed to kill container: {str(e)}")

    def is_connected(self) -> bool:
        """
        Check if Docker daemon is connected
        
        Returns:
            True if connected, False otherwise
        """
        if not self.client:
            return False
            
        try:
            return self.client.ping()
        except:
            return False
