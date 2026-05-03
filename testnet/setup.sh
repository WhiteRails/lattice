#!/bin/bash
set -e

# 2. Start Services & Overlay Network
echo "Starting backend mock services..."
npm run services:echo &
ECHO_PID=$!
npm run services:github &
GITHUB_PID=$!
sleep 2

echo "Starting WhiteNet Relay Node..."
npm run whitenet -- node start --role relay --port 8888 &
RELAY_PID=$!
sleep 1

echo "Starting WhiteNet Service Gateways..."
npm run whitenet -- node start --role gateway --service wp://echo.white --target http://127.0.0.1:9001 --port 8889 &
GW1_PID=$!
npm run whitenet -- node start --role gateway --service wp://github.white --target http://127.0.0.1:9002 --port 8890 &
GW2_PID=$!
sleep 1

echo "Starting WhiteNet Entry Node..."
npm run whitenet -- node start --role entry --port 7777 &
ENTRY_PID=$!
sleep 2

echo "Waiting 5 seconds for services to start..."
sleep 5

echo "Running test agent..."
npm run whitenet -- run --agent bot1 --no-internet -- node examples/agents/node-agent.js

echo "Test agent finished. Inspecting logs..."
npm run whitenet -- logs tail --n 5

# Cleanup
echo "Killing services..."
kill $ECHO_PID $GITHUB_PID $RELAY_PID $GW1_PID $GW2_PID $ENTRY_PID
wait $ECHO_PID $GITHUB_PID $RELAY_PID $GW1_PID $GW2_PID $ENTRY_PID 2>/dev/null || true
echo "Done."
