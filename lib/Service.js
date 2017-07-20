const crypto = require('crypto');
const { Service } = require('engined');
const jwt = require('jsonwebtoken');

module.exports = (opts = {}) => class extends Service {

	constructor(context) {
		super(context);

		this.agentName = opts.agentName || 'default';
		this.dbAgentName = opts.dbAgentName || 'default';
		this.expiresIn = opts.expiresIn || 30 * 24 * 60 * 60 * 1000;
		this.secret = opts.secret || '';
	}

	async start() {

		let context = this.getContext().get('Member');
		if (!context) {
			context = {};
			this.getContext().set('Member', context);
		}

		// Add agent
		context[this.agentName] = {
			dbAgentName: this.dbAgentName,
			generateSalt: () => {
				return crypto.randomBytes(12).toString('base64');
			},
			generateJwtToken: (payload) => {

				return jwt.sign(payload, this.secret, {
					expiresIn: this.expiresIn
				}, { algorithm: 'HS512' });
			},
			encryptPassword: (salt, password) => {
				return crypto.createHmac('sha256', password + salt || '').digest('hex');
			},
			Permission: {
				middlewares: {

				}
			}
		};
	}

	async stop() {

		let context = this.getContext().get('Member');
		if (!context) {
			return;
		}

		// Take off agent from context
		delete context[this.agentName];

		if (Object.keys(context).length === 0)
			this.getContext().set('Member', undefined);
	}
}
