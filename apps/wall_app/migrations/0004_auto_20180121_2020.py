# -*- coding: utf-8 -*-
# Generated by Django 1.11 on 2018-01-22 04:20
from __future__ import unicode_literals

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('wall_app', '0003_comment_user'),
    ]

    operations = [
        migrations.RenameField(
            model_name='comment',
            old_name='user',
            new_name='poster',
        ),
        migrations.RemoveField(
            model_name='message',
            name='user',
        ),
        migrations.AddField(
            model_name='message',
            name='poster',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='posted_messages', to='wall_app.User'),
            preserve_default=False,
        ),
        migrations.AddField(
            model_name='message',
            name='receiver',
            field=models.ForeignKey(default='', on_delete=django.db.models.deletion.CASCADE, related_name='received_messages', to='wall_app.User'),
            preserve_default=False,
        ),
    ]
