import json
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from .models import User, Token


class FriendRequestConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get user ID from URL path
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.user = await self.get_user(self.user_id)

        if not self.user:
            await self.close()
            return

        self.room_group_name = f'user_{self.user_id}'

        # Join user's personal group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave user's personal group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def receive(self, text_data):
        data = json.loads(text_data)
        message_type = data.get('type')

        if message_type == 'send_friend_request':
            token = data.get('token')
            recipient_id = data.get('recipient_id')

            if token and recipient_id:
                result = await self.handle_friend_request(token, recipient_id)
                await self.send(text_data=json.dumps(result))

    async def friend_request(self, event):
        """ Send friend request notification to the recipient """
        await self.send(text_data=json.dumps({
            'type': 'friend_request',
            'sender': event['sender'],
            'sender_id': event['sender_id'],
            'message': event['message'],
            'action': 'refresh_requests'
        }))

    async def friend_request_accepted(self, event):
        """ Send notification that a friend request was accepted """
        await self.send(text_data=json.dumps({
            'type': 'friend_request_accepted',
            'friend': event['friend'],
            'friend_id': event['friend_id'],
            'message': event['message'],
            'action': 'refresh_friends'
        }))

    async def friend_request_declined(self, event):
        """ Send notification that a friend request was declined """
        await self.send(text_data=json.dumps({
            'type': 'friend_request_declined',
            'user': event['user'],
            'user_id': event['user_id'],
            'message': event['message'],
            'action': 'refresh_all_users'
        }))

    @database_sync_to_async
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None

    @database_sync_to_async
    def handle_friend_request(self, token, recipient_id):
        try:
            token_obj = Token.objects.get(token=token)
            if not token_obj.is_valid():
                return {'error': 'Token has expired', 'status': 401}

            sender = token_obj.user

            try:
                recipient = User.objects.get(id=recipient_id)
            except User.DoesNotExist:
                return {'error': 'Recipient user not found', 'status': 404}

            # Check if users are already friends
            if recipient in sender.friends.all():
                return {'error': 'Users are already friends', 'status': 400}

            # Check if friend request is already sent
            if recipient in sender.friend_requests_sent.all():
                return {'error': 'Friend request already sent', 'status': 400}

            # Check if recipient has already sent a request to sender
            if sender in recipient.friend_requests_sent.all():
                # Auto-accept the request, making them friends
                sender.friends.add(recipient)
                # Remove the pending request
                recipient.friend_requests_sent.remove(sender)

                # Notify both users about the new friendship
                return {
                    'type': 'friend_request_accepted',
                    'message': f'You and {recipient.name or recipient.email} are now friends',
                    'friend_id': recipient.id,
                    'friend': recipient.name or recipient.email,
                    'status': 200
                }

            # Send friend request
            sender.friend_requests_sent.add(recipient)

            return {
                'type': 'friend_request_sent',
                'message': f'Friend request sent to {recipient.name or recipient.email}',
                'recipient_id': recipient.id,
                'recipient': recipient.name or recipient.email,
                'status': 200
            }

        except Token.DoesNotExist:
            return {'error': 'Invalid token', 'status': 401}


# Keeping the original ChatConsumer implementation to avoid breaking changes
class ChatConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        self.roomGroupName = "group_chat_gfg"
        await self.channel_layer.group_add(
            self.roomGroupName,
            self.channel_name
        )
        await self.accept()

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(
            self.roomGroupName,
            self.channel_name
        )

    async def receive(self, text_data):
        text_data_json = json.loads(text_data)
        message = text_data_json["message"]
        username = text_data_json["username"]
        await self.channel_layer.group_send(
            self.roomGroupName, {
                "type": "sendMessage",
                "message": message,
                "username": username,
            })

    async def sendMessage(self, event):
        message = event["message"]
        username = event["username"]
        await self.send(text_data=json.dumps({"message": message, "username": username}))


class ChatNotificationConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Get user ID from URL path
        self.user_id = self.scope['url_route']['kwargs']['user_id']
        self.user = await self.get_user(self.user_id)

        if not self.user:
            await self.close()
            return

        self.room_group_name = f'chat_notifications_{self.user_id}'

        # Join user's personal notification group
        await self.channel_layer.group_add(
            self.room_group_name,
            self.channel_name
        )

        await self.accept()

    async def disconnect(self, close_code):
        # Leave notification group
        await self.channel_layer.group_discard(
            self.room_group_name,
            self.channel_name
        )

    async def new_message_notification(self, event):
        """Send notification about new message to the recipient"""
        await self.send(text_data=json.dumps({
            'type': 'new_message',
            'sender_id': event['sender_id'],
            'sender_name': event['sender_name'],
            'message_preview': event['message_preview'],
            'actions': ['refresh_unread', 'refresh_recent']
        }))

    @database_sync_to_async
    def get_user(self, user_id):
        try:
            return User.objects.get(id=user_id)
        except User.DoesNotExist:
            return None
