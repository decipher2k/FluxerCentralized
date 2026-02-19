const condition = (hasDependency) => hasDependency('sass') || hasDependency('sass-embedded') || hasDependency('node-sass');
const importMatcher = /@(?:use|import|forward)\s+['"](pkg:)?([^'"]+)['"]/g;
const toRelative = (specifier) => (specifier.startsWith('.') ? specifier : `./${specifier}`);
const compiler = (text) => {
    const imports = [];
    let match;
    let index = 0;
    while ((match = importMatcher.exec(text))) {
        if (match[2] && !match[2].startsWith('sass:'))
            imports.push(`import _$${index++} from '${match[1] ? match[2] : toRelative(match[2])}';`);
    }
    return imports.join('\n');
};
export default { condition, compiler };
