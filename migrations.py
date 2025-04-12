import hashlib
import logging
from sqlalchemy import Column, String
from CTFd.models import db
from .models import ContainerFlagModel, generate_flag_hash

logger = logging.getLogger(__name__)

def upgrade_flag_model():
    """
    Run migration to add and populate flag_hash column for existing flags
    
    This should be called during plugin initialization if needed
    """
    try:
        # Check if flag_hash column exists
        inspector = db.inspect(db.engine)
        if 'flag_hash' not in [col['name'] for col in inspector.get_columns('container_flag_model')]:
            logger.info("Adding flag_hash column to container_flag_model table")
            
            # Add column
            db.engine.execute('ALTER TABLE container_flag_model ADD COLUMN flag_hash VARCHAR(64)')
            
            # Create index
            db.engine.execute('CREATE INDEX ix_container_flag_model_flag_hash ON container_flag_model (flag_hash)')
            
            # Update existing records
            update_count = 0
            flags = db.session.query(ContainerFlagModel).all()
            for flag in flags:
                if flag.flag:
                    flag.flag_hash = generate_flag_hash(flag.flag)
                    update_count += 1
            
            db.session.commit()
            logger.info(f"Updated {update_count} existing flag records with hash values")
            
            # Add uniqueness constraint
            db.engine.execute('CREATE UNIQUE INDEX uix_container_flag_model_flag_hash ON container_flag_model (flag_hash)')
            
            return True
    except Exception as e:
        logger.error(f"Error upgrading flag model: {e}")
        db.session.rollback()
        return False
    
    return False  # No upgrade needed 