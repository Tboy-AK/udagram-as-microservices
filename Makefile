build:
	docker build -t udagram-api-feed ./udagram-api-feed
	docker build -t udagram-api-user ./udagram-api-user
	docker build -t udagram-reverseproxy ./udagram-reverseproxy
	docker build -t udagram-frontend ./udagram-frontend
tag: build
	docker tag udagram-api-feed "${DOCKER_USERNAME}"/udagram-api-feed:v1
	docker tag udagram-api-user "${DOCKER_USERNAME}"/udagram-api-user:v1
	docker tag udagram-reverseproxy "${DOCKER_USERNAME}"/udagram-reverseproxy:v1
	docker tag udagram-frontend "${DOCKER_USERNAME}"/udagram-frontend:v1
push: tag
	echo "${DOCKER_PASSWORD}" | docker login -u "${DOCKER_USERNAME}" --password-stdin
	docker push "${DOCKER_USERNAME}"/udagram-api-feed:v1
	docker push "${DOCKER_USERNAME}"/udagram-api-user:v1
	docker push "${DOCKER_USERNAME}"/udagram-reverseproxy:v1
	docker push "${DOCKER_USERNAME}"/udagram-frontend:v1
