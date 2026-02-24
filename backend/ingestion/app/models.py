from . import database 
from datetime import datetime

class LogEntry(database.Model):
    __tablename__ = 'logs'

    id = database.Column(database.Integer, primary_key=True)
    source = database.Column(database.String(50))
    raw_data = database.Column(database.JSON)
    natural_language_summary = database.Column(database.Text)
    normalized_data = database.Column(database.JSON)
    timestamp = database.Column(database.DateTime)
    created_at = database.Column(database.DateTime, default=datetime.timezone.utc) 


