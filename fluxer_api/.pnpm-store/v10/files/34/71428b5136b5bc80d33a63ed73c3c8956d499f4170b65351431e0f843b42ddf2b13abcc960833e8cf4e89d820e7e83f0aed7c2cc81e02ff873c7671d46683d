import { forEachAliasReExport, forEachNamespaceReExport, forEachPassThroughReExport, getStarReExportSources, } from '../visitors.js';
export const hasStrictlyNsReferences = (graph, importsForExport, identifier) => {
    if (!importsForExport)
        return [false];
    let foundNamespace;
    const aliasByIdentifier = new Map();
    const namespaceReExports = new Map();
    const namespaceEdges = [];
    const directById = new Map();
    forEachPassThroughReExport(importsForExport, (id, sources) => {
        directById.set(id, sources);
    });
    forEachAliasReExport(importsForExport, (id, alias, sources) => {
        let arr = aliasByIdentifier.get(id);
        if (!arr) {
            arr = [];
            aliasByIdentifier.set(id, arr);
        }
        arr.push({ alias, sources });
    });
    forEachNamespaceReExport(importsForExport, (namespace, sources) => {
        namespaceEdges.push({ namespace, sources });
        let arr = namespaceReExports.get(namespace);
        if (!arr) {
            arr = [];
            namespaceReExports.set(namespace, arr);
        }
        arr.push(sources);
    });
    const starSources = getStarReExportSources(importsForExport);
    const followReExports = (sources, nextId, propagateNamespace = true) => {
        for (const filePath of sources) {
            const file = graph.get(filePath);
            if (!file?.imported)
                continue;
            const result = hasStrictlyNsReferences(graph, file.imported, nextId);
            if (result[0] === false)
                return result;
            if (propagateNamespace && result[1])
                foundNamespace = result[1];
        }
        return undefined;
    };
    for (const ns of importsForExport.importedNs.keys()) {
        const hasNsRef = importsForExport.refs.has(ns);
        if (!hasNsRef)
            return [false, ns];
        for (const ref of importsForExport.refs) {
            if (ref.startsWith(`${ns}.`))
                return [false, ns];
        }
        const nsReExports = namespaceReExports.get(ns);
        if (nsReExports) {
            for (const sources of nsReExports) {
                const result = followReExports(sources, identifier, false);
                if (result)
                    return result;
            }
        }
        const nsAliases = aliasByIdentifier.get(ns);
        if (nsAliases) {
            for (const { sources } of nsAliases) {
                const result = followReExports(sources, identifier, false);
                if (result)
                    return result;
            }
        }
        foundNamespace = ns;
    }
    const directSources = directById.get(identifier);
    if (directSources) {
        const result = followReExports(directSources, identifier, true);
        if (result)
            return result;
    }
    if (starSources) {
        const result = followReExports(starSources, identifier, true);
        if (result)
            return result;
    }
    const [id, ...rest] = identifier.split('.');
    const aliasEntries = aliasByIdentifier.get(id);
    if (aliasEntries) {
        for (const { alias, sources } of aliasEntries) {
            const result = followReExports(sources, [alias, ...rest].join('.'), true);
            if (result)
                return result;
        }
    }
    for (const { namespace: ns, sources } of namespaceEdges) {
        const result = followReExports(sources, `${ns}.${identifier}`, true);
        if (result)
            return result;
    }
    if (foundNamespace)
        return [true, foundNamespace];
    return [false];
};
