const child_process = require("child_process");
const fs = require("fs");
const path = require("path");

function runCommand(userInput) {
  return child_process.exec(`ping -c 1 ${userInput}`);
}

function calculate(expression) {
  return eval(expression);
}

function findUser(db, username) {
  return db.query(`SELECT * FROM users WHERE username = '${username}'`);
}

function readUserFile(filename) {
  return fs.readFileSync(path.join("/srv/uploads", filename), "utf8");
}

async function fetchRemote(req) {
  return fetch(req.query.url);
}

const apiKey = "DEMO_JAVASCRIPT_API_KEY_123456";
