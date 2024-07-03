#!/usr/bin/env node
const fs = require('fs');
const http = require('http');

class WorkerClient {
    constructor(baseUrl) {
        this.baseUrl = baseUrl;
    }

    async init() {
        await this.initWorkerIfNot();
    }

    async initWorkerIfNot() {
        console.log('Checking worker info...');
        const workerInfo = await this.rpcCall("Info", {});
        if (!workerInfo.session || workerInfo.session === "0x") {
            console.log('No active session found, initializing worker...');
            await this.rpcCall("WorkerInit", {});
            console.log('Worker initialized.');
        } else {
            console.log('Active session found, worker already initialized.');
        }
    }

    async uploadFile(fileName) {
        console.log('Uploading file:', fileName);
        const data = fs.readFileSync(fileName);
        return await this.rpcCall("BlobPut", {
            body: data.toString('hex')
        });
    }

    async deploy(manifest) {
        return await this.rpcCall("AppDeploy", { manifest });
    }

    async rpcCall(method, params) {
        const url = `${this.baseUrl}/prpc/Operation.${method}?json`;
        const response = await httpPost(url, params);
        return JSON.parse(response);
    }
}

function httpPost(url, jsonData) {
    return new Promise((resolve, reject) => {
        const data = JSON.stringify(jsonData);
        const { hostname, pathname, port } = new URL(url);

        const options = {
            hostname,
            port: port || 80,
            path: pathname,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': data.length
            }
        };

        const req = http.request(options, (res) => {
            let responseData = '';
            res.on('data', chunk => responseData += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    resolve(responseData);
                } else {
                    const errorMsg = `HTTP status code ${res.statusCode}: ${responseData}`;
                    reject(new Error(errorMsg));
                }
            });
        });

        req.on('error', error => {
            reject(error);
        });
        req.write(data);
        req.end();
    });
}

async function main() {
    const WAPOD_URL = process.env.WAPOD_URL || "http://127.0.0.1:8001";
    const wasmFile = process.argv[2];
    if (!wasmFile) {
        console.error('Usage: deploy.js <wasm_file>');
        console.error('Please provide a wasm file to deploy.');
        process.exit(1);
    }

    try {
        const client = new WorkerClient(WAPOD_URL);
        await client.init();

        const wasmFileInfo = await client.uploadFile(wasmFile);

        const manifest = {
            version: 1,
            code_hash: wasmFileInfo.hash,
            args: [],
            env_vars: [["RUST_LOG", "debug"]],
            on_demand: false,
            resizable: true,
            max_query_size: 10240,
            label: "Test App",
        };

        console.log('Deploying app...');
        const appInfo = await client.deploy(manifest);
        console.log('App deployed, address is', appInfo.address);
    } catch (error) {
        console.error('An error occurred during the main process:', error);
    }
}

main().catch(console.error);