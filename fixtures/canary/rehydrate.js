var cache = {}

function rehydrate(payload) {
    return eval(payload)
}

module.exports = { rehydrate: rehydrate }
