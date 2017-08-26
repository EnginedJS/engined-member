const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const PermissionManager = require('../lib/PermissionManager');
const MemberManager = require('../lib/MemberManager');
const RelationalMap = require('./RelationalMap');

module.exports = class Agent {

	constructor(service) {
		this.service = service;
		this.permissionManager = new PermissionManager(this);
		this.memberManager = new MemberManager(this);

		// Options
		this.options = Object.assign({
			agentName: 'default',
			httpAgent: 'default',
			dbAgent: 'default',
			storageAgent: 'default',
			expiresIn: 30 * 24 * 60 * 60 * 1000,
			secret: '',
			signInUrl: '/signin',
			accountIsDisabledByDefault: false
		}, service.opts);

		// Initializing data models
		this.dataMap = new RelationalMap();
		this.dataMap.applyDbSchema(this.service.data.get('DataModel').Database);
		this.dataMap.applyViewSchema(this.service.data.get('DataModel').View);
	}

	async initialize() {
		await this.initializeDatabase();
		await this.initializeHTTPMiddleware();
		await this.initializePermissions();
	}

	async initializeHTTPMiddleware() {

		const httpAgent = this.getContext().get('HTTP')[this.options.httpAgent];

		// Setup Session middleware
		httpAgent.use(async (ctx, next) => {

			if (ctx.state === undefined)
				ctx.state = {};

			// not yet authorized
			if (!ctx.headers.authorization) {
				await next();
				return;
			}

			// Getting JWT token
			let authString = ctx.headers.authorization.split(' ');
			if (authString[0] !== 'JWT') {
				await next();
				return;
			}

			try {
				// Decode payload from JWT token
				let payload = this.decodeJwtToken(authString[1]);
				ctx.state.session = payload;
			} catch(e) {
				// failed to decode invalid token
			}

			await next();
		});
	}

	async initializeDatabase() {

		// Getting database agent
		const dbAgent = this.getContext().get('MySQL').getAgent(this.options.dbAgent);

		// Getting database models
		const models = this.service.data.get('DataModel').Database;

		await dbAgent.assertModels(models);
	}

	async initializePermissions() {

		const permissions = [
			() => {
				// Setup permission for member who logined already
				const handler = this
					.getPermissionManager()
					.registerPermission('Member', 'access', 'Standard member access rights');

				handler.check(async (ctx, next) => {

					// Check whether user is disabled or not
					if (await this.getMemberManager().isDisabled(ctx.state.session.id)) {

						if (ctx.state.routeType === 'API') {
							ctx.throw(403);
						} else {
							// TODO: redirect to page for disabled account
							return;
						}
					}

					// Getting latest permissions from database
					ctx.state.session.perms = await this 
						.getPermissionManager()
						.getPermissions(ctx.state.session.id);

					ctx.state.session.disabled = false;

					await next();
				});
			},
			() => {

				// Setup permission for reset password
				this
					.getPermissionManager()
					.registerPermission('Member', 'reset.password', 'reset password rights');
			},
			() => {

				// Setup permission for managing members
				this
					.getPermissionManager()
					.registerPermission('Member', 'list', 'list members rights');
			},
			() => {

				// Setup permission for administrator
				const adminHandler = this
					.getPermissionManager()
					.registerPermission('Admin', 'access', 'Standard administrator access rights');

				adminHandler.check(async (ctx, next) => {

					// Check whether user is disabled or not
					if (await this.getMemberManager().isDisabled(ctx.state.session.id)) {

						if (ctx.state.routeType === 'API') {
							ctx.throw(403);
						} else {
							// TODO: redirect to page for disabled account
							return;
						}
					}

					// Getting latest permissions from database
					ctx.state.session.perms = await this
						.getPermissionManager()
						.getPermissions(ctx.state.session.id);

					ctx.state.session.disabled = false;

					await next();
				});
			}
		];

		// Waiting for registration tasks get done
		permissions.map((register) => register());
	}

	getView(viewName) {
		return this.dataMap.getView(viewName);
	}

	getValidationRules(name) {
		return this.service.data.get('DataModel').Validation[name];
	}

	generateSalt() {
		return crypto.randomBytes(12).toString('base64');
	}

	generateJwtToken(payload, expiresIn) {

		// Packing token
		return jwt.sign(payload, this.options.secret, {
			expiresIn: expiresIn || this.options.expiresIn
		}, { algorithm: 'HS512' });
	}

	decodeJwtToken(token) {
		return jwt.verify(token, this.options.secret);
	}

	encryptPassword(salt, password) {
		return crypto.createHmac('sha256', password + salt || '').digest('hex');
	}

	getContext() {
		return this.service.getContext();
	}

	getOptions() {
		return this.options;
	}

	getMemberManager() {
		return this.memberManager;
	}

	getPermissionManager() {
		return this.permissionManager;
	}

	getPermissionMiddleware() {
		return this.permissionManager.getMiddleware();
	}
};
