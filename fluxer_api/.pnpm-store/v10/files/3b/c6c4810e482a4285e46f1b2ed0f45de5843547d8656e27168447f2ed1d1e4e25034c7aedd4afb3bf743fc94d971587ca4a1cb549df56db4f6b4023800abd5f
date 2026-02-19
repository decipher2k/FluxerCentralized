"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.isObject = isObject;
exports.isPlainObject = isPlainObject;
function isObject(input) {
    return input != null && typeof input === 'object';
}
const ObjectProto = Object.prototype;
const ObjectToString = Object.prototype.toString;
function isPlainObject(input) {
    if (!input || typeof input !== 'object')
        return false;
    const proto = Object.getPrototypeOf(input);
    if (proto === null)
        return true;
    return ((proto === ObjectProto ||
        // Needed to support NodeJS's `runInNewContext` which produces objects
        // with a different prototype
        Object.getPrototypeOf(proto) === null) &&
        ObjectToString.call(input) === '[object Object]');
}
//# sourceMappingURL=object.js.map