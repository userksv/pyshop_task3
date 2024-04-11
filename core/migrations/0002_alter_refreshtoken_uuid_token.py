# Generated by Django 5.0.4 on 2024-04-11 02:11

import uuid
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
    ]

    operations = [
        migrations.AlterField(
            model_name='refreshtoken',
            name='uuid_token',
            field=models.UUIDField(default=uuid.uuid4, unique=True),
        ),
    ]
