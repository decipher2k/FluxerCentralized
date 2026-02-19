"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isBlobRef = isBlobRef;
exports.isLegacyBlobRef = isLegacyBlobRef;
const cid_js_1 = require("./cid.js");
const object_js_1 = require("./object.js");
function isBlobRef(input, options) {
    if (!(0, object_js_1.isPlainObject)(input)) {
        return false;
    }
    if (input?.$type !== 'blob') {
        return false;
    }
    const { mimeType, size, ref } = input;
    // @NOTE Very basic mime validation
    if (typeof mimeType !== 'string' || !mimeType.includes('/')) {
        return false;
    }
    if (typeof size !== 'number' || size < 0 || !Number.isInteger(size)) {
        return false;
    }
    if (typeof ref !== 'object' || ref === null) {
        return false;
    }
    for (const key in input) {
        if (key !== '$type' &&
            key !== 'mimeType' &&
            key !== 'ref' &&
            key !== 'size') {
            return false;
        }
    }
    const cid = (0, cid_js_1.asCid)(ref);
    if (!cid) {
        return false;
    }
    if (options?.strict) {
        if (cid.version !== 1) {
            return false;
        }
        if (cid.code !== cid_js_1.RAW_BIN_MULTICODEC) {
            return false;
        }
        if (cid.multihash.code !== cid_js_1.SHA2_256_MULTIHASH_CODE) {
            return false;
        }
    }
    return true;
}
function isLegacyBlobRef(input) {
    if (!(0, object_js_1.isPlainObject)(input)) {
        return false;
    }
    const { cid, mimeType } = input;
    if (typeof cid !== 'string') {
        return false;
    }
    if (typeof mimeType !== 'string') {
        return false;
    }
    for (const key in input) {
        if (key !== 'cid' && key !== 'mimeType') {
            return false;
        }
    }
    try {
        (0, cid_js_1.parseCid)(cid);
    }
    catch {
        return false;
    }
    return true;
}
//# sourceMappingURL=blob.js.map