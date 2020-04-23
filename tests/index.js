const wallet = require('../main.js');

function generate(passphrase, salt, power, coin) {
	console.log("Generating " + coin)
	return new Promise(resolve => {
		wallet.generateWallet(passphrase, salt, power, coin,(result, wallet) => {
			if (wallet) {
				resolve(wallet)
			}
		});
	})
}

(async () => {
	const coins = ['bitcoin', 'litecoin', 'monero', 'ethereum', 'segwit']
	const power = 'default';

	for(let coin of coins) {
		try {
			const result = await generate('pass', 'salt', power, coin);
			console.log(result)
		} catch (e) {
			console.log(e)
		}
	}
})();
