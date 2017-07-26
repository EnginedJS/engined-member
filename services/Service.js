const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Service } = require('engined');
const Agent = require('../lib/Agent');
const Permission = require('../lib/Permission');

module.exports = (opts = {}) => class extends Service {

	constructor(context) {
		super(context);

		this.agent = null;
		this.agentName = opts.agentName || 'default';
		this.httpAgent = opts.httpAgent || 'default';
		this.dbAgent = opts.dbAgent || 'default';
		this.expiresIn = opts.expiresIn || 30 * 24 * 60 * 60 * 1000;
		this.secret = opts.secret || '';
		this.perms = {};
		this.signInUrl = '/signin';
		this.defaultReject = async (ctx, next) => {

			// Redirect to login page
			ctx.redirect(this.signInUrl);
		};
	}

	async start() {

		let context = this.getContext().get('Member');
		if (!context) {
			context = {};
			this.getContext().set('Member', context);
		}

		let httpAgent = this.getContext().get('HTTP')[this.httpAgent];

		// Setup Session middleware
		httpAgent.use(async (ctx, next) => {

			if (ctx.state === undefined)
				ctx.state = {};

			// not yet authorized
			if (ctx.headers.Authorization === undefined) {
				await next();
				return;
			}

			// Getting member agent
			let agent = this.getContext().get('Member')[this.agentName];

			// Getting JWT token
			let authString = ctx.headers.Authorzation.split(' ');
			if (authString[0] !== 'JWT') {
				await next();
				return;
			}

			// Decode payload from JWT token
			let payload = agent.decodeJwtToken(authString[1]);

			ctx.state.session = payload;

			await next();
		});

		// Add agent
		this.agent = context[this.agentName] = new Agent(this);

		// Setup permission for member who logined already
		this.agent.getPermissionManager().registerPermission('Member', 'access');
	}

	async stop() {

		this.agent = null;

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
