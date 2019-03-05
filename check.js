const pathToRegexp = require('path-to-regexp');

module.exports = function check(table, reqUrl, reqMethod='') {
    return table.map(v=>[].concat(v)).find(entry => {
        const [testUrl, testMethod=''] = entry
        return (typeof testMethod!=='string' || reqMethod.match(new RegExp(testMethod, 'i')))
            && pathToRegexp(testUrl).exec(reqUrl)
    });
}
