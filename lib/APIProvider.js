const Router = require('koa-router');
const { RouterService } = require('engined-http');
const RestPack = require('restpack');

const createRouter = (service) => {

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
		let password = payload.password;

		if (!email) {
			pkg
				.setStatus(RestPack.Status.ValidationFailed)
				.appendError('email', RestPack.Code.Required)
				.sendKoa(ctx);

			return;
		}

		// Getting member system agent
		let agent = ctx.enginedContext.get('Member')[service.useAgentName];

		// Getting database agent
		let dbAgent = ctx.enginedContext.get('MySQL')[agent.dbAgentName];

		// Finding member by using email
		let qstr = [
			'SELECT `name`, `email`, `salt`, `password`',
			'FROM `members`',
			'WHERE',
			'`email` = ?'
		].join(' ');
		let [ records ] = await dbAgent.query(qstr, [ email ]);
		if (records[0].length === 0)
			ctx.throw(401);

		// Check password
		if (agent.encryptPassword(records[0].salt, password) !== records[0].password)
			ctx.throw(401);

		// Prepare JWT package for user
		pkg
			.setData({
				token: agent.generateJwtToken({
					id: records[0].id,
					name: records[0].name,
					email: records[0].email
				})
			})
			.sendKoa(ctx);
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
		let agent = ctx.enginedContext.get('Member')[service.useAgentName];

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

		// Finding member by using email
		try {
			let qstr = [
				'INSERT INTO `members` SET ?' 
			].join(' ');

			let [ ret ] = await dbAgent.query(qstr, {
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
			ctx.throw(500);
		}

		// Prepare JWT package for user
		pkg
			.setData({
				token: agent.generateJwtToken({
					id: ret.insertId,
					email: email
				})
			})
			.sendKoa(ctx);
	});

	return router;
};

module.exports = (opts) => class extends RouterService() {

	constructor(context) {
		super(context);

		this.useAgentName = opts.useAgentName || 'default';
	}

	async setupRoutes() {
		return createRouter(this);
	}
};
