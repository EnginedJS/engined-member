const Router = require('koa-router');
const { RouterService } = require('engined-http');
const RestPack = require('restpack');
const MemberAPI = require('../lib/Member');
const PermissionAPI = require('../lib/Permission');

const createRouter = (service) => {

	// Getting member system agent
	const memberAPI = MemberAPI(service);
	const permissionAPI = PermissionAPI(service);

	// Create a new router
	let router = Router({
		prefix: '/api/v1/member'
	});

	/*
	 * @api {post} /api/v1/member/auth Authorize account to sign in
	 * @apiName Authorize
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 422 {Object} ValidationFailed Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	{
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 1  }
	 *		]
	 *	}
	 */
	router.post('/auth', async (ctx, next) => {

		if (!ctx.request.body)
			ctx.throw(400);

		// Create a package for restful API
		let pkg = new RestPack();

		let payload = ctx.request.body;
		let email = payload.email;
		let password = payload.password || '';

		if (!email) {
			pkg
				.setStatus(RestPack.Status.ValidationFailed)
				.appendError('email', RestPack.Code.Required)
				.sendKoa(ctx);

			return;
		}

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.memberAgent];

		try {
			// Verify member account
			let member = await memberAPI.verify(email, password);

			// Getting permissions
			let permissions = await permissionAPI.getPermissions(member.id);

			// Prepare JWT package for user
			pkg
				.setData({
					token: agent.generateJwtToken({
						id: member.id,
						name: member.name,
						email: member.email,
						perms: permissions
					})
				})
				.sendKoa(ctx);
		} catch(e) {

			switch(e.name) {
			case 'NotExist':
			case 'VerificationFailed':
				ctx.throw(401);
			}

			console.log(e);
		}
	});

	/*
	 * @api {post} /api/v1/member/signup Sign up an account
	 * @apiName SignUp
	 * @apiGroup Member
	 *
	 * @apiParam {String} email member's email
	 * @apiParam {String} password password
	 *
	 * @apiSuccess {String} token Access token
	 * @apiError 400 {String} BadRequest
	 * @apiError 409 {String} MemberExistsAlready
	 * @apiError 422 {Object} ValidationFailed Parameters are invalid
	 * @apiErrorExample {json} Error-Response:
	 *	{
	 *		message: 'Validation Failed',
	 *		errors: [
	 *			{ field: 'email', code: 1  }
	 *		]
	 *	}
	 */
	router.post('/signup', async (ctx) => {

		if (!ctx.request.body)
			ctx.throw(400);

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.memberAgent];

		// Create a package for restful API
		let pkg = new RestPack();

		let payload = ctx.request.body;
		let email = payload.email;

		if (!email) {
			pkg
				.setStatus(RestPack.Status.ValidationFailed)
				.appendError('email', RestPack.Code.Required)
				.sendKoa(ctx);

			return;
		}

		// Encrypt password
		let salt = agent.generateSalt();
		let password = agent.encryptPassword(salt, payload.password);

		// Getting database agent
		let dbAgent = ctx.enginedContext.get('MySQL')[agent.dbAgentName];

		// Create member
		let ret;
		try {
			[ ret ] = await dbAgent.query('INSERT INTO `Member` SET ?', {
				email: email,
				password: password,
				salt: salt
			});
		} catch(e) {

			// Account exists already
			if (e.code === 'ER_DUP_ENTRY') {
				ctx.throw(409, 'Account exists already');
			}

			ctx.throw(500);
		}

		if (ret.affectedRows === 0) {
			// Failed to insert record
			ctx.throw(500);
		}

		// Add permissions
		let permissions = [
			'Member.access'
		];
		await agent.getPermissionManager().addPermission(ret.insertId, permissions);

		// Prepare JWT package for user
		pkg
			.setData({
				token: agent.generateJwtToken({
					id: ret.insertId,
					email: email,
					perms: permissions
				})
			})
			.sendKoa(ctx);
	});

	return router;
};

module.exports = (opts) => class extends RouterService() {

	constructor(context) {
		super(context);

		this.memberAgent = opts.memberAgent || 'default';
	}

	async setupRoutes() {
		return createRouter(this);
	}
};
