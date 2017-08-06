const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const PermissionManager = require('../lib/PermissionManager');
const MemberManager = require('../lib/MemberManager');
const RelationalMap = require('./RelationalMap');

module.exports = class Agent {

	constructor(service) {
		this.service = service;
		this.dbAgent = service.dbAgent;
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
			accountIsDisabledByDefault: false,
			dbSchema: {
				Member: {
					id: Joi.number().required(),
					name: Joi.string().max(255).required(),
					email: Joi.string().email().max(512).required(),
					password: Joi.string().required(),
					salt: Joi.string().required(),
					phone: Joi.string().max(64),
					avatar_url: Joi.string().max(255),
					country: Joi.string().max(255),
					address: Joi.string().max(255),
					city: Joi.string().max(255),
					state: Joi.string().max(255),
					zip_code: Joi.string().max(64),
					disabled: Joi.number(),
					created: Joi.date()
				}
			},
			validations: {
				VerifyMember: {
					email: Joi.string().email().required(),
					password: Joi.string().required()
				},
				CreateMember: {
					name: Joi.string().required(),
					email: Joi.string().email().required(),
					password: Joi.string().required()
				},
				UpdateProfile: {
					email: Joi.string().email().required(),
					name: Joi.string().required(),
					phone: Joi.string(),
					country: Joi.string(),
					address: Joi.string(),
					city: Joi.string(),
					state: Joi.string(),
					zip_code: Joi.string()
				}
			},
			views: {
				CreateMember: {
					schema: {
						email: 'Member.email',
						name: 'Member.name',
						password: 'Member.password'
					}
				},
				VerifyMember: {
					schema: {
						id: 'Member.id',
						name: 'Member.name',
						email: 'Member.email'
					}
				},
				GetProfile: {
					schema: {
						email: 'Member.email',
						name: 'Member.name',
						phone: 'Member.phone',
						avatar_url: 'Member.avatar_url',
						country: 'Member.country',
						address: 'Member.address',
						city: 'Member.city',
						state: 'Member.state',
						zip_code: 'Member.zip_code',
						created: 'Member.created'
					}
				},
				UpdateProfile: {
					schema: {
						email: 'Member.email',
						name: 'Member.name',
						phone: 'Member.phone',
						country: 'Member.country',
						address: 'Member.address',
						city: 'Member.city',
						state: 'Member.state',
						zip_code: 'Member.zip_code'
					}
				}
			}
		}, service.opts);

		// Initializing relational map
		this.dataMap = new RelationalMap();
		this.dataMap.applyDbSchema(this.options.dbSchema);
		this.dataMap.applyViewSchema(this.options.views);
	}

	getView(viewName) {
		return this.dataMap.getView(viewName);
	}

	getValidationRules(name) {
		return this.options.validations[name];
	}

	generateSalt() {
		return crypto.randomBytes(12).toString('base64');
	}

	generateJwtToken(payload) {

		// Packing token
		return jwt.sign(payload, this.options.secret, {
			expiresIn: this.options.expiresIn
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

	getMemberSchema() {
		return this.options.memberSchema;
	}

	getSchemaChecker(name) {
		// TODO: implement memoization to improve performance
		return this.options.schemaChecker[name](this.options.memberSchema);
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
