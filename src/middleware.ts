import { defineMiddleware } from "astro:middleware";

export const onRequest = defineMiddleware((context, next) => {
	if (context.url.hostname === "[::1]") {
		return context.redirect(context.url.href.replace("[::1]", "localhost"));
	}
	return next();
});
