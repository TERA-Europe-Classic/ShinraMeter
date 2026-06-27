using Data;
using Data.Actions;
using Data.Events.Abnormality;
using System.Collections.Generic;
using System.Windows.Threading;

namespace DamageMeter.UI
{
    public class AbnormalityEventViewModel : BaseEventViewModel
    {
        private readonly AbnormalityEvent _event;
        private readonly List<string> _eventNames;

        public SynchronizedObservableCollection<AbnormalityVM> Abnormalities { get; }

        private AbnormalityTargetType _target;
        private AbnormalityTriggerType _trigger;
        private int _secondsBeforeTrigger;
        private int _rewarnTimeout;

        public AbnormalityTargetType Target
        {
            get => _target;
            set
            {
                if (_target == value) return;
                _target = value;
                _event.Target = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(Summary));
                RefreshSearchText();
            }
        }

        public AbnormalityTriggerType Trigger
        {
            get => _trigger;
            set
            {
                if (_trigger == value) return;
                _trigger = value;
                _event.Trigger = value;
                NotifyPropertyChanged();
                NotifyPropertyChanged(nameof(Summary));
                RefreshSearchText();
            }
        }

        public int SecondsBeforeTrigger
        {
            get => _secondsBeforeTrigger;
            set
            {
                if (_secondsBeforeTrigger == value) return;
                _secondsBeforeTrigger = value;
                _event.RemainingSecondBeforeTrigger = value;
                NotifyPropertyChanged();
                RefreshSearchText();
            }
        }

        public int RewarnTimeout
        {
            get => _rewarnTimeout;
            set
            {
                if (_rewarnTimeout == value) return;
                _rewarnTimeout = value;
                _event.RewarnTimeoutSeconds = value;
                NotifyPropertyChanged();
                RefreshSearchText();
            }
        }

        public override string Type => "Abnormality event";
        public override string Summary => $"{Trigger} {Target}: {string.Join(", ", _eventNames)}";
        protected override string BuildSearchText() => $"{base.BuildSearchText()} {Target} {Trigger} {SecondsBeforeTrigger} {RewarnTimeout} {string.Join(" ", _eventNames)}";

        public AbnormalityEventViewModel(AbnormalityEvent ev, List<Action> act) : base(ev, act)
        {
            _event = ev;
            Abnormalities = new SynchronizedObservableCollection<AbnormalityVM>(Dispatcher.CurrentDispatcher);

            _target = ev.Target;
            _trigger = ev.Trigger;
            _secondsBeforeTrigger = ev.RemainingSecondBeforeTrigger;
            _rewarnTimeout = ev.RewarnTimeoutSeconds;

            foreach (var (abId, stacks) in ev.Ids)
            {
                Abnormalities.Add(new AbnormalityVM(abId, stacks));
            }

            foreach (var type in ev.Types)
            {
                Abnormalities.Add(new AbnormalityVM(type));
            }

            _eventNames = new List<string>(EventNames());
            RefreshSearchText();
        }

        private IEnumerable<string> EventNames()
        {
            foreach (var (id, stacks) in _event.Ids)
            {
                var name = BasicTeraData.Instance.HotDotDatabase?.Get(id)?.Name;
                var suffix = stacks > 0 ? $" x{stacks}" : "";
                yield return string.IsNullOrWhiteSpace(name) ? $"{id}{suffix}" : $"{name} ({id}{suffix})";
            }

            foreach (var type in _event.Types)
            {
                yield return type.ToString();
            }
        }
    }
}
