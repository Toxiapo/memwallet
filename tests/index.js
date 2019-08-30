const wallet = require('../main.js');

function generate(passphrase, salt, coin) {
	console.log("Generating " + coin)
	return new Promise(resolve => {
		wallet.generateWallet(passphrase, salt, coin,(result, wallet) => {
			if (wallet) {
				resolve(wallet)
			}
		});
	})
}

(async () => {
	const coins = ['bitcoin', 'litecoin', 'monero', 'ethereum', 'segwit']

	for(let coin of coins) {
		try {
			const result = await generate('pass', 'salt', coin);
			console.log(result)
		} catch (e) {
			console.log(e)
		}
	}
})();
