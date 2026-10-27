FROM nginx:alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY index.html manifest.webmanifest icon.svg sw.js supabase-config.js /usr/share/nginx/html/
EXPOSE 8080
