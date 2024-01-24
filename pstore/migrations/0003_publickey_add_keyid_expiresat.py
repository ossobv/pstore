# Generated by Django 4.1.10 on 2024-01-24 14:01

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pstore', '0002_add_read_at'),
    ]

    operations = [
        migrations.AddField(
            model_name='publickey',
            name='expires_at',
            field=models.DateTimeField(blank=True, default=None, editable=False, null=True),
        ),
        migrations.AddField(
            model_name='publickey',
            name='key_id',
            field=models.CharField(blank=True, default='', editable=False, max_length=255),
        ),
    ]
