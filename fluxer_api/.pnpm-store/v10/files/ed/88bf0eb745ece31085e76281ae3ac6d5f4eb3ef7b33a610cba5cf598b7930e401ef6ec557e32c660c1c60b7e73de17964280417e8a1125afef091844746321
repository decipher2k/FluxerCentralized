"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isLexMap = isLexMap;
exports.isLexArray = isLexArray;
exports.isLexScalar = isLexScalar;
exports.isLexValue = isLexValue;
exports.isTypedLexMap = isTypedLexMap;
const cid_js_1 = require("./cid.js");
const object_js_1 = require("./object.js");
function isLexMap(value) {
    if (!(0, object_js_1.isPlainObject)(value))
        return false;
    for (const key in value) {
        if (!isLexValue(value[key]))
            return false;
    }
    return true;
}
function isLexArray(value) {
    if (!Array.isArray(value))
        return false;
    for (let i = 0; i < value.length; i++) {
        if (!isLexValue(value[i]))
            return false;
    }
    return true;
}
function isLexScalar(value) {
    switch (typeof value) {
        case 'object':
            if (value === null)
                return true;
            return value instanceof Uint8Array || (0, cid_js_1.isCid)(value);
        case 'string':
        case 'boolean':
            return true;
        case 'number':
            if (Number.isInteger(value))
                return true;
            throw new TypeError(`Invalid Lex value: ${value}`);
        default:
            throw new TypeError(`Invalid Lex value: ${typeof value}`);
    }
}
function isLexValue(value) {
    switch (typeof value) {
        case 'number':
            if (!Number.isInteger(value))
                return false;
        // fallthrough
        case 'string':
        case 'boolean':
            return true;
        case 'object':
            if (value === null)
                return true;
            if (Array.isArray(value)) {
                for (let i = 0; i < value.length; i++) {
                    if (!isLexValue(value[i]))
                        return false;
                }
                return true;
            }
            if ((0, object_js_1.isPlainObject)(value)) {
                for (const key in value) {
                    if (!isLexValue(value[key]))
                        return false;
                }
                return true;
            }
            if (value instanceof Uint8Array)
                return true;
            if ((0, cid_js_1.isCid)(value))
                return true;
        // fallthrough
        default:
            return false;
    }
}
function isTypedLexMap(value) {
    return (isLexMap(value) && typeof value.$type === 'string' && value.$type.length > 0);
}
//# sourceMappingURL=lex.js.map