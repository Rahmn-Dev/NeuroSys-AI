from chatbot.models import ChatMessage, ChatSession
ChatMessage.objects.all().delete()
ChatSession.objects.all().delete()
print("Chat history wiped successfully.")
