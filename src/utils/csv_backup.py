import os
import csv
from datetime import datetime, timedelta

class CSVBackup:
    @staticmethod
    def rotate_logs(logs_dir='./logs', days_to_keep=30):
        """Elimina logs más antiguos que days_to_keep"""
        cutoff_date = datetime.now() - timedelta(days=days_to_keep)
        
        for filename in os.listdir(logs_dir):
            if filename.endswith('.csv'):
                file_path = os.path.join(logs_dir, filename)
                file_time = datetime.fromtimestamp(os.path.getctime(file_path))
                
                if file_time < cutoff_date:
                    os.remove(file_path)
                    print(f"Removed old log: {filename}")

    @staticmethod
    def write_csv(file_path, headers, data):
        """Escribe datos a CSV de forma segura"""
        try:
            with open(file_path, 'w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                writer.writerow(headers)
                writer.writerows(data)
            return True
        except Exception as e:
            print(f"Backup error: {e}")
            return False
