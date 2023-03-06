import sqlite3
import bleach

class DatabaseUtils:

    def __init__(self, database_name='common_db.db'):
        self.database_name = database_name
    
    def fetch_data(self, query, params):
        '''
        For select queries. Fetches data from the database and returns as a list of rows
        '''

        # Validating input: Check for null or empty values
        if not params:
            raise "username or password cannot be null or empty"

        # sanitize input further
        # ref: https://bleach.readthedocs.io/en/latest/clean.html
        # This function is a security-focused function
        # whose sole purpose is to remove malicious content from a string
        # such that it can be displayed as content in a web page.
        params = [bleach.clean(p) for p in params]

        with sqlite3.connect(self.database_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            rows = cursor.fetchall()
        return rows
    
    def update_data(self, query, params):
        '''
        For all table modification queries which make changes to the database
        '''
        with sqlite3.connect(self.database_name) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
    
