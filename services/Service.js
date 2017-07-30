const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { Service } = require('engined');
const Agent = require('../lib/Agent');
const Joi = require('joi');

module.exports = (opts = {}) => class extends Service {

	constructor(context) {
		super(context);

		this.agent = null;
		this.opts = opts;
		this.agentName = opts.agentName || 'default';
		this.httpAgent = opts.httpAgent || 'default';
		this.dbAgent = opts.dbAgent || 'default';
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
			if (!ctx.headers.authorization) {
				await next();
				return;
			}

			// Getting member agent
			let agent = this.getContext().get('Member')[this.agentName];

			// Getting JWT token
			let authString = ctx.headers.authorization.split(' ');
			if (authString[0] !== 'JWT') {
				await next();
				return;
			}

			try {
				// Decode payload from JWT token
				let payload = agent.decodeJwtToken(authString[1]);
				ctx.state.session = payload;
			} catch(e) {
				// failed to decode invalid token
			}

			await next();
		});

		// Add agent
		this.agent = context[this.agentName] = new Agent(this);

		// Setup permission for member who logined already
		let handler = this.agent
			.getPermissionManager()
			.registerPermission('Member', 'access', 'Standard member access rights');

		handler.check(async (ctx, next) => {

			// Check whether user is disabled or not
			if (await this.agent.getMemberManager().isDisabled(ctx.state.session.id)) {

				if (ctx.state.routeType === 'API') {
					ctx.throw(403);
				} else {
					// TODO: redirect to page for disabled account
					return;
				}
			}

			ctx.state.session.disabled = false;
			await next();
		});

		// Setup permission for administrator
		let adminHandler = this.agent
			.getPermissionManager()
			.registerPermission('Admin', 'access', 'Standard administrator access rights');

		adminHandler.check(async (ctx, next) => {

			// Check whether user is disabled or not
			if (await this.agent.getMemberManager().isDisabled(ctx.state.session.id)) {

				if (ctx.state.routeType === 'API') {
					ctx.throw(403);
				} else {
					// TODO: redirect to page for disabled account
					return;
				}
			}

			ctx.state.session.disabled = false;
			await next();
		});

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
