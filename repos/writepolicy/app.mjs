#!/usr/local/bin/node

import * as readline from "readline";
import * as fs from "fs";
import { Reader } from "@maxmind/geoip2-node";
const IPCIDR = (await import("ip-cidr")).default;
import path from "path";
import { fileURLToPath } from "url";
import * as ElasticSearch from "@elastic/elasticsearch";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const AsnDbBuffer = fs.readFileSync(__dirname + "/maxmind/GeoLite2-ASN.mmdb");
const AsnReader = Reader.openBuffer(AsnDbBuffer);

const CountryDbBuffer = fs.readFileSync(__dirname + "/maxmind/GeoLite2-Country.mmdb");
const CountryReader = Reader.openBuffer(CountryDbBuffer);

// const esClient = new ElasticSearch.Client({ host: "elasticsearch:9100" });

const kindAllowList = {
  0: true,
  2: true,
  3: true,
  5: true,
  6: true,
  7: true,
  8: true,
  1984: true,
  9735: true,
  10000: true,
  10001: true,
  10002: true,
  30000: true,
  30001: true,
  30008: true,
  30009: true,
}

const ipAllowList = [
  "127.0.0.0/8",
  "192.168.0.0/16",
  "172.16.0.0/12",
  "10.0.0.0/8",
  "fd00::/8",
]

const pubkeyAllowList = {
  "b707d6be7fd9cc9e1aee83e81c3994156cfcf74ded5b09111930fdeeeb5a0c20": true, //It's me!
};

const AsnDenyList = {
  20473: true,
};

const CountryAllowList = {
  "JP": true,
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
  terminal: false,
});

console.error(process.env);

rl.on("line", (line) => {
  console.error(line);
  let req = JSON.parse(line);
  let res = {};
  try {
    res = { id: req.event.id }; // must echo the event"s id
  } catch (error) {
    console.error(error);
    return;
  }

  if (process.env.CHAT === "deny" && (req.event.kind === 4 || (40 <= req.event.kind && req.event.kind <= 49))) {
    res.action = "reject";
    res.msg = "blocked: Event not allowed";
    console.log(JSON.stringify(res));
    return;
  }

  if (req.type === "lookback") {
    return;
  }

  if (req.sourceType === "Stream") {
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (req.type !== "new") {
    console.error("unexpected request type"); // will appear in strfry logs
    return;
  }

  if (pubkeyAllowList[req.event.pubkey]) {
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (kindAllowList[req.event.kind]) {
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  let isLocalIp = false;
  ipAllowList.some((value) => {
    if (!IPCIDR.isValidCIDR(value)) {
      return;
    }
    let cidr = new IPCIDR(value);
    if (cidr.contains(req.sourceInfo)) {
      isLocalIp = true;
      return true;
    } else {
      return false;
    }
  });
  if (isLocalIp) {
    res.action = "accept";
    console.log(JSON.stringify(res));
    return;
  }

  if (AsnDenyList[AsnReader.asn(req.sourceInfo).autonomousSystemNumber]) {
    res.action = "reject";
    res.msg = "blocked: ASN not allowed";
    console.log(JSON.stringify(res));
    return;
  }

  if (!CountryAllowList[CountryReader.country(req.sourceInfo).registeredCountry.isoCode]) {
    res.action = "reject";
    res.msg = "blocked: Country not allowed";
    console.log(JSON.stringify(res));
    return;
  }

  res.action = "accept";
  console.log(JSON.stringify(res));
  return;
});