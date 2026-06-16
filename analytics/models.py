from django.db import models

# Create your models here.
class LogEntry(models.Model):
    class LogLevel(models.TextChoices):
        INFO = 'INFO', 'Information'
        WARN = 'WARN', 'Warning'
        ERROR = 'ERROR', 'Error'
    timestamp = models.DateTimeField(db_index=True)
    ip_address = models.GenericIPAddressField(db_index=True)
    level = models.CharField(
        max_length= 5,
        choices= LogLevel.choices,
        default= LogLevel.INFO
    )
    message = models.TextField()

    class Meta:
        verbose_name_plural = "Log Entries"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.timestamp} - {self.ip_address} - {self.level}"
    