#!/usr/bin/env bash

ps auxww | grep "queue=qa-daily" | awk '{print $2}' | sudo xargs kill -9

