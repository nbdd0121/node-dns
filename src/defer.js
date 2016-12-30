export default function Defer() {
    let resolve, reject;
    let promise = new Promise(function(res, rej) {
        resolve = res;
        reject = rej;
    });
    return {
        resolve: resolve,
        reject: reject,
        promise: promise
    };
}

